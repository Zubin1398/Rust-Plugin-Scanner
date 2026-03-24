from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    category: str
    title: str
    description: str
    patterns: List[str]
    false_positive_hints: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    rule: Rule
    line_no: int
    line_text: str
    match_text: str
    filepath: str = ""
