//! Ephemeral line selections derived from the exact Markdown bytes being searched.

use std::ops::Range;

use nexus_search_common::discovery::{MarkdownBlock, StructuralFilter};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

use crate::search_proto::GrepSection;

pub(crate) struct LineSelection {
    ranges: Vec<Range<usize>>,
    pub section: Option<GrepSection>,
}

impl LineSelection {
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn contains(&self, line: usize) -> bool {
        let index = self.ranges.partition_point(|range| range.end <= line);
        self.ranges
            .get(index)
            .is_some_and(|range| range.start <= line)
    }
}

fn is_markdown(path: &str) -> bool {
    let extension = path.rsplit('.').next().unwrap_or("");
    ["md", "markdown", "mdown", "mkd"]
        .iter()
        .any(|suffix| extension.eq_ignore_ascii_case(suffix))
}

/// Non-Markdown files pass a block filter unchanged; section searches exclude them.
pub(crate) fn select_lines(
    path: &str,
    text: &str,
    filter: &StructuralFilter,
) -> Option<LineSelection> {
    if !filter.is_active() || (!is_markdown(path) && filter.section.is_none()) {
        return None;
    }
    if !is_markdown(path) {
        return Some(LineSelection {
            ranges: Vec::new(),
            section: None,
        });
    }
    let mut line_starts = vec![0];
    line_starts.extend(
        text.bytes()
            .enumerate()
            .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
    );
    let total_lines = line_starts.len() - usize::from(line_starts.last() == Some(&text.len()));
    let line_at = |byte: usize| line_starts.partition_point(|start| *start <= byte) - 1;
    let mut ranges: Vec<Range<usize>> = Vec::new();
    let mut sections: Vec<GrepSection> = Vec::new();
    let mut open_sections: Vec<usize> = Vec::new();
    let mut heading = None;
    let mut paragraph_blocks = Vec::new();
    let options = Options::ENABLE_TABLES | Options::ENABLE_YAML_STYLE_METADATA_BLOCKS;
    for (event, bytes) in Parser::new_ext(text, options).into_offset_iter() {
        if filter.block == Some(MarkdownBlock::Paragraph) {
            // CommonMark tight lists emit their paragraph's inline events
            // directly inside Item. Nested headings, code and other blocks
            // have their own tags and must retain their distinct block type.
            match &event {
                Event::Start(tag) if !is_inline(tag.to_end()) => {
                    paragraph_blocks.push(tag.to_end());
                }
                Event::End(tag) if !is_inline(*tag) => {
                    paragraph_blocks.pop();
                }
                Event::End(_) | Event::Rule => {}
                _ if paragraph_blocks.last() == Some(&TagEnd::Item) && bytes.end > bytes.start => {
                    let selected = line_at(bytes.start)..line_at(bytes.end - 1) + 1;
                    if let Some(last) = ranges.last_mut().filter(|last| last.end >= selected.start)
                    {
                        last.end = last.end.max(selected.end);
                    } else {
                        ranges.push(selected);
                    }
                }
                _ => {}
            }
        }
        match event {
            Event::Start(tag) => {
                let kind = match tag {
                    Tag::Paragraph => Some(MarkdownBlock::Paragraph),
                    Tag::Heading { level, .. } => {
                        if filter.section.is_some() {
                            let line = line_at(bytes.start);
                            let depth = level as u32;
                            while open_sections
                                .last()
                                .is_some_and(|index| sections[*index].depth >= depth)
                            {
                                let index = open_sections.pop().unwrap();
                                sections[index].line_end = line as u32;
                            }
                            let index = sections.len();
                            sections.push(GrepSection {
                                heading: String::new(),
                                depth,
                                line_start: line as u32 + 1,
                                line_end: total_lines as u32,
                            });
                            open_sections.push(index);
                            heading = Some(index);
                        }
                        Some(MarkdownBlock::Heading)
                    }
                    Tag::CodeBlock(_) => Some(MarkdownBlock::Code),
                    Tag::Table(_) => Some(MarkdownBlock::Table),
                    Tag::BlockQuote(_) => Some(MarkdownBlock::Blockquote),
                    Tag::List(_) => Some(MarkdownBlock::List),
                    Tag::MetadataBlock(_) => Some(MarkdownBlock::Frontmatter),
                    _ => None,
                };
                if kind.is_some() && kind == filter.block && bytes.end > bytes.start {
                    ranges.push(line_at(bytes.start)..line_at(bytes.end - 1) + 1);
                }
            }
            Event::Text(text) | Event::Code(text) => {
                if let Some(index) = heading {
                    sections[index].heading.push_str(&text);
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                if let Some(index) = heading {
                    sections[index].heading.push(' ');
                }
            }
            Event::End(TagEnd::Heading(_)) => heading = None,
            _ => {}
        }
    }
    let section = filter.section.as_ref().and_then(|query| {
        let eligible = |section: &&GrepSection| {
            !section.heading.is_empty() && query.depth.is_none_or(|depth| depth == section.depth)
        };
        sections
            .iter()
            .filter(eligible)
            .find(|section| section.heading.to_lowercase() == query.heading)
            .or_else(|| {
                sections
                    .iter()
                    .filter(eligible)
                    .find(|section| section.heading.to_lowercase().contains(&query.heading))
            })
            .cloned()
    });
    if filter.block.is_none() {
        ranges.push(0..total_lines);
    }
    if filter.section.is_some() {
        match &section {
            Some(section) => {
                let start = section.line_start as usize - 1;
                let end = section.line_end as usize;
                for range in &mut ranges {
                    range.start = range.start.max(start);
                    range.end = range.end.min(end);
                }
                ranges.retain(|range| !range.is_empty());
            }
            None => ranges.clear(),
        }
    }
    // Container and child blocks can overlap; union them to keep lookup bounded.
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(last) = merged.last_mut().filter(|last| last.end >= range.start) {
            last.end = last.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    Some(LineSelection {
        ranges: merged,
        section,
    })
}

fn is_inline(tag: TagEnd) -> bool {
    matches!(
        tag,
        TagEnd::Emphasis
            | TagEnd::Strong
            | TagEnd::Strikethrough
            | TagEnd::Superscript
            | TagEnd::Subscript
            | TagEnd::Link
            | TagEnd::Image
    )
}
