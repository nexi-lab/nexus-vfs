//! Validation shared by discovery entry points, without VFS or parser dependencies.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkdownBlock {
    Code,
    Table,
    Frontmatter,
    Paragraph,
    Blockquote,
    List,
    Heading,
}

impl MarkdownBlock {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "code" => Ok(Self::Code),
            "table" => Ok(Self::Table),
            "frontmatter" => Ok(Self::Frontmatter),
            "paragraph" => Ok(Self::Paragraph),
            "blockquote" => Ok(Self::Blockquote),
            "list" => Ok(Self::List),
            "heading" => Ok(Self::Heading),
            _ => Err("block_type must be code, table, frontmatter, paragraph, blockquote, list or heading".into()),
        }
    }
}

#[derive(Debug)]
pub struct SectionQuery {
    pub heading: String,
    pub depth: Option<u32>,
}

impl SectionQuery {
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("section must contain a heading".into());
        }
        let hashes = value.bytes().take_while(|byte| *byte == b'#').count();
        let (heading, depth) =
            if (1..=6).contains(&hashes) && value[hashes..].starts_with(char::is_whitespace) {
                (value[hashes..].trim(), Some(hashes as u32))
            } else {
                (value, None)
            };
        if heading.is_empty() {
            return Err("section must contain a heading".into());
        }
        Ok(Self {
            heading: heading.to_lowercase(),
            depth,
        })
    }
}

#[derive(Debug)]
pub struct StructuralFilter {
    pub block: Option<MarkdownBlock>,
    pub section: Option<SectionQuery>,
}

impl StructuralFilter {
    pub fn parse(block: Option<&str>, section: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            block: block.map(MarkdownBlock::parse).transpose()?,
            section: section.map(SectionQuery::parse).transpose()?,
        })
    }

    pub fn is_active(&self) -> bool {
        self.block.is_some() || self.section.is_some()
    }
}
