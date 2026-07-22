use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub summary: String,
    pub details: Option<String>,
    pub severity: Option<Severity>,
    #[serde(default)]
    pub references: Vec<Reference>,
    #[serde(default)]
    pub affected: Vec<Affected>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Severity {
    #[serde(rename = "type")]
    pub type_: String,
    pub score: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityBand {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score_value(&self) -> Option<f32> {
        if let Ok(score) = self.score.parse::<f32>() {
            return valid_score(score);
        }

        parse_cvss_vector(&self.type_, &self.score).and_then(valid_score)
    }

    pub fn severity_band(&self) -> SeverityBand {
        let Some(score) = self.score_value() else {
            return SeverityBand::Unknown;
        };
        if self.type_.eq_ignore_ascii_case("CVSS_V2") {
            if score >= 7.0 {
                SeverityBand::High
            } else if score >= 4.0 {
                SeverityBand::Medium
            } else {
                SeverityBand::Low
            }
        } else if score >= 9.0 {
            SeverityBand::Critical
        } else if score >= 7.0 {
            SeverityBand::High
        } else if score >= 4.0 {
            SeverityBand::Medium
        } else {
            SeverityBand::Low
        }
    }

    pub fn severity_label(&self) -> &'static str {
        match self.severity_band() {
            SeverityBand::Unknown => "Unknown",
            SeverityBand::Low => "Low",
            SeverityBand::Medium => "Medium",
            SeverityBand::High => "High",
            SeverityBand::Critical => "Critical",
        }
    }
}

impl Vulnerability {
    pub fn severity_band(&self) -> SeverityBand {
        self.severity
            .as_ref()
            .map_or(SeverityBand::Unknown, Severity::severity_band)
    }
}

fn valid_score(score: f32) -> Option<f32> {
    (score.is_finite() && (0.0..=10.0).contains(&score)).then_some(score)
}

fn parse_cvss_vector(severity_type: &str, vector: &str) -> Option<f32> {
    if severity_type.eq_ignore_ascii_case("CVSS_V2") {
        return parse_cvss_v2(vector);
    }
    if severity_type.eq_ignore_ascii_case("CVSS_V3") {
        return parse_cvss_v3(vector);
    }
    if severity_type.eq_ignore_ascii_case("CVSS_V4") {
        return parse_cvss_v4(vector);
    }
    None
}

fn parse_cvss_v3(vector: &str) -> Option<f32> {
    use cvss::v3::Base as V3Base;

    if let Ok(cvss) = vector.parse::<V3Base>() {
        return Some(cvss.score().value() as f32);
    }

    let base_only = strip_to_base_metrics(vector);
    if base_only != vector
        && let Ok(cvss) = base_only.parse::<V3Base>()
    {
        return Some(cvss.score().value() as f32);
    }

    None
}

fn parse_cvss_v4(vector: &str) -> Option<f32> {
    use cvss::v4::Vector as V4Vector;

    if let Ok(cvss) = vector.parse::<V4Vector>() {
        return Some(cvss.score().value() as f32);
    }

    let base_only = strip_to_base_metrics(vector);
    if base_only != vector
        && let Ok(cvss) = base_only.parse::<V4Vector>()
    {
        return Some(cvss.score().value() as f32);
    }

    None
}

fn parse_cvss_v2(vector: &str) -> Option<f32> {
    let vector = vector
        .strip_prefix("CVSS:2.0/")
        .or_else(|| vector.strip_prefix("CVSS2#"))
        .unwrap_or(vector);
    let mut access_vector = None;
    let mut access_complexity = None;
    let mut authentication = None;
    let mut confidentiality = None;
    let mut integrity = None;
    let mut availability = None;

    for metric in vector.split('/') {
        let (name, value) = metric.split_once(':')?;
        let value = value.to_ascii_uppercase();
        let target = match name {
            "AV" => (
                &mut access_vector,
                metric_value(&value, &[('L', 0.395), ('A', 0.646), ('N', 1.0)]),
            ),
            "AC" => (
                &mut access_complexity,
                metric_value(&value, &[('H', 0.35), ('M', 0.61), ('L', 0.71)]),
            ),
            "Au" => (
                &mut authentication,
                metric_value(&value, &[('M', 0.45), ('S', 0.56), ('N', 0.704)]),
            ),
            "C" => (&mut confidentiality, impact_metric(&value)),
            "I" => (&mut integrity, impact_metric(&value)),
            "A" => (&mut availability, impact_metric(&value)),
            _ => continue,
        };
        if target.0.replace(target.1?).is_some() {
            return None;
        }
    }

    let impact =
        10.41 * (1.0 - (1.0 - confidentiality?) * (1.0 - integrity?) * (1.0 - availability?));
    let exploitability = 20.0 * access_vector? * access_complexity? * authentication?;
    let impact_factor = if impact == 0.0 { 0.0 } else { 1.176 };
    let score = ((0.6 * impact + 0.4 * exploitability - 1.5) * impact_factor).clamp(0.0, 10.0);
    Some(((score * 10.0_f64) + 0.5).floor() as f32 / 10.0)
}

fn metric_value(value: &str, values: &[(char, f64)]) -> Option<f64> {
    let key = value.chars().next().filter(|_| value.len() == 1)?;
    values
        .iter()
        .find_map(|(name, value)| (*name == key).then_some(*value))
}

fn impact_metric(value: &str) -> Option<f64> {
    metric_value(value, &[('N', 0.0), ('P', 0.275), ('C', 0.660)])
}

/// Remove metrics outside the CVSS base group.
fn strip_to_base_metrics(vector: &str) -> String {
    const BASE_METRICS: &[&str] = &[
        "AV", "AC", "PR", "UI", "S", "C", "I", "A", "Au", "AT", "VC", "VI", "VA", "SC", "SI", "SA",
    ];

    let mut parts = vector.split('/');
    let Some(prefix) = parts.next() else {
        return vector.to_string();
    };

    let mut out = String::with_capacity(vector.len());
    out.push_str(prefix);
    for part in parts {
        let metric = part.split(':').next().unwrap_or("");
        if BASE_METRICS.contains(&metric) {
            out.push('/');
            out.push_str(part);
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    #[serde(rename = "type")]
    pub type_: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Affected {
    pub package: Package,
    #[serde(default)]
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub ecosystem: String,
    #[serde(default)]
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default)]
    pub events: Vec<RangeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnResult {
    pub purl: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[cfg(test)]
mod tests {
    use super::{Severity, SeverityBand, parse_cvss_vector};

    #[test]
    fn severity_score_parses_float() {
        let severity = Severity {
            type_: "CVSS_V3".to_string(),
            score: "9.8".to_string(),
        };
        let score = severity.score_value().expect("score should parse");
        assert!((score - 9.8).abs() < f32::EPSILON);
    }

    #[test]
    fn severity_score_handles_invalid() {
        let severity = Severity {
            type_: "CVSS_V3".to_string(),
            score: "not-a-score".to_string(),
        };
        assert!(severity.score_value().is_none());
    }

    #[test]
    fn severity_score_rejects_non_finite_and_out_of_range_values() {
        for score in ["NaN", "inf", "-0.1", "10.1"] {
            let severity = Severity {
                type_: "CVSS_V3".to_string(),
                score: score.to_string(),
            };
            assert!(severity.score_value().is_none(), "score={score}");
            assert_eq!(severity.severity_band(), SeverityBand::Unknown);
        }
    }

    #[test]
    fn severity_score_parses_cvss_vector() {
        let severity = Severity {
            type_: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string(),
        };
        let score = severity.score_value().expect("cvss vector should parse");
        assert!((score - 8.8).abs() < 0.1, "Expected 8.8, got {score}");
    }

    #[test]
    fn cvss_vector_critical_severity() {
        let score = parse_cvss_vector("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
            .expect("should parse");
        assert!(score >= 9.0, "Expected critical (>=9.0), got {score}");
    }

    #[test]
    fn cvss_vector_high_severity() {
        let score = parse_cvss_vector("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
            .expect("should parse");
        assert!(
            (7.0..9.0).contains(&score),
            "Expected high (7.0-8.9), got {score}"
        );
    }

    #[test]
    fn cvss_vector_medium_severity() {
        let score = parse_cvss_vector("CVSS_V3", "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L")
            .expect("should parse");
        assert!(
            (4.0..7.0).contains(&score),
            "Expected medium (4.0-6.9), got {score}"
        );
    }

    #[test]
    fn cvss_vector_low_severity() {
        let score = parse_cvss_vector("CVSS_V3", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
            .expect("should parse");
        assert!(
            score > 0.0 && score < 4.0,
            "Expected low (0.1-3.9), got {score}"
        );
    }

    #[test]
    fn cvss_vector_no_impact() {
        let score = parse_cvss_vector("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
            .expect("should parse");
        assert!(
            (score - 0.0).abs() < f32::EPSILON,
            "Expected 0.0, got {score}"
        );
    }

    #[test]
    fn cvss_v4_vector() {
        let score = parse_cvss_vector(
            "CVSS_V4",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        )
        .expect("should parse CVSS v4");
        assert!(score >= 9.0, "Expected critical CVSS v4 score, got {score}");
    }

    #[test]
    fn cvss_v3_vector_with_temporal_metric() {
        // OSV publishes this temporal metric for Log4Shell.
        let score = parse_cvss_vector(
            "CVSS_V3",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H",
        )
        .expect("temporal-laden vector should still yield a base score");
        assert!(
            (score - 10.0).abs() < f32::EPSILON,
            "Expected base score 10.0 for Log4Shell, got {score}"
        );
    }

    #[test]
    fn cvss_v3_vector_with_full_environmental_metrics() {
        let score = parse_cvss_vector(
            "CVSS_V3",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/MAV:N",
        )
        .expect("should recover base score from a fully-decorated vector");
        assert!(score >= 9.0, "Expected critical base score, got {score}");
    }

    #[test]
    fn cvss_v4_vector_with_threat_metric() {
        let score = parse_cvss_vector(
            "CVSS_V4",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
        )
        .expect("should parse v4 vector with threat metric");
        assert!(score >= 9.0, "Expected critical CVSS v4 score, got {score}");
    }

    #[test]
    fn severity_label_critical_for_log4shell_vector() {
        let severity = Severity {
            type_: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H".to_string(),
        };
        assert_eq!(severity.severity_label(), "Critical");
    }

    #[test]
    fn severity_label_from_score() {
        let critical = Severity {
            type_: "CVSS_V3".to_string(),
            score: "9.8".to_string(),
        };
        assert_eq!(critical.severity_label(), "Critical");

        let high = Severity {
            type_: "CVSS_V3".to_string(),
            score: "8.5".to_string(),
        };
        assert_eq!(high.severity_label(), "High");

        let medium = Severity {
            type_: "CVSS_V3".to_string(),
            score: "5.0".to_string(),
        };
        assert_eq!(medium.severity_label(), "Medium");

        let low = Severity {
            type_: "CVSS_V3".to_string(),
            score: "2.0".to_string(),
        };
        assert_eq!(low.severity_label(), "Low");
    }

    #[test]
    fn cvss_v2_vectors_use_v2_scores_and_bands() {
        let high = Severity {
            type_: "CVSS_V2".to_string(),
            score: "AV:N/AC:L/Au:N/C:P/I:P/A:P".to_string(),
        };
        assert_eq!(high.score_value(), Some(7.5));
        assert_eq!(high.severity_band(), SeverityBand::High);

        let maximum = Severity {
            type_: "CVSS_V2".to_string(),
            score: "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C".to_string(),
        };
        assert_eq!(maximum.score_value(), Some(10.0));
        assert_eq!(maximum.severity_band(), SeverityBand::High);
        assert_eq!(maximum.severity_label(), "High");
    }

    #[test]
    fn cvss_vector_parser_dispatches_by_osv_severity_type() {
        let v2_vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P";
        assert_eq!(parse_cvss_vector("CVSS_V2", v2_vector), Some(7.5));
        assert_eq!(parse_cvss_vector("CVSS_V3", v2_vector), None);
        assert_eq!(parse_cvss_vector("OTHER", v2_vector), None);
    }
}
