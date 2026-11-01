use serde::{Deserialize, Serialize};

/// One OSV vulnerability record, mirroring the fields of the
/// [OSV schema](https://ossf.github.io/osv-schema/) that raeva reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Vulnerability {
    /// OSV `id`, such as `GHSA-...` or `CVE-...`.
    pub id: String,
    /// OSV `aliases`: ids of the same issue in other databases.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// OSV `summary`, empty when the record has none.
    pub summary: String,
    /// OSV `details`, the advisory text in CommonMark.
    pub details: Option<String>,
    /// The entry of OSV `severity` with a usable score from the newest
    /// CVSS version, the highest by band and then score among several.
    /// When no entry has a usable score it is the first entry, and `None`
    /// when the record lists none.
    pub severity: Option<Severity>,
    /// OSV `database_specific.severity`, such as `HIGH` or `MODERATE` in
    /// GitHub advisories. It sets the band when [`Self::severity`] has no
    /// usable score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_severity: Option<String>,
    /// OSV `references`.
    #[serde(default)]
    pub references: Vec<Reference>,
    /// OSV `affected`.
    #[serde(default)]
    pub affected: Vec<Affected>,
}

/// One entry of the OSV `severity` list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Severity {
    /// OSV `severity[].type`, such as `CVSS_V3`, `CVSS_V4` or `CVSS_V2`.
    #[serde(rename = "type")]
    pub type_: String,
    /// OSV `severity[].score`: a CVSS vector for the CVSS types, or
    /// another scale's value for other types.
    pub score: String,
}

/// Qualitative severity, ordered from [`Unknown`](Self::Unknown) up to
/// [`Critical`](Self::Critical), with the CVSS rating bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityBand {
    /// No severity, or a score that cannot be parsed or is outside 0 to 10.
    Unknown,
    /// Score 0.0.
    None,
    /// Score from 0.1 to below 4.0.
    Low,
    /// Score from 4.0 to below 7.0.
    Medium,
    /// Score from 7.0 to below 9.0, or 7.0 and above for `CVSS_V2`.
    High,
    /// Score 9.0 and above, never for `CVSS_V2`, which has no such band.
    Critical,
}

impl Severity {
    /// The numeric score from 0 to 10. A plain number is taken as is;
    /// otherwise a `CVSS_V2`, `CVSS_V3` or `CVSS_V4` vector is scored from
    /// its base metrics. `None` for anything else or a value outside the
    /// range.
    pub fn score_value(&self) -> Option<f32> {
        let score = match self.score.parse::<f32>() {
            Ok(score) => score,
            Err(_) => match self.type_.to_ascii_uppercase().as_str() {
                "CVSS_V2" => cvss_v2_score(&self.score)?,
                "CVSS_V3" => base_score(&self.score, |v: cvss::v3::Vector| v.score().value())?,
                "CVSS_V4" => base_score(&self.score, |v: cvss::v4::Vector| v.score().value())?,
                _ => return None,
            },
        };
        (score.is_finite() && (0.0..=10.0).contains(&score)).then_some(score)
    }

    /// The band of [`Self::score_value`], [`SeverityBand::Unknown`] when
    /// there is no score.
    pub fn severity_band(&self) -> SeverityBand {
        let Some(score) = self.score_value() else {
            return SeverityBand::Unknown;
        };
        let critical = if self.type_.eq_ignore_ascii_case("CVSS_V2") {
            f32::INFINITY
        } else {
            9.0
        };
        match score {
            score if score >= critical => SeverityBand::Critical,
            score if score >= 7.0 => SeverityBand::High,
            score if score >= 4.0 => SeverityBand::Medium,
            score if score > 0.0 => SeverityBand::Low,
            _ => SeverityBand::None,
        }
    }
}

impl Vulnerability {
    /// The band of [`Self::severity`], else of [`Self::database_severity`],
    /// else [`SeverityBand::Unknown`].
    pub fn severity_band(&self) -> SeverityBand {
        let band = self
            .severity
            .as_ref()
            .map_or(SeverityBand::Unknown, Severity::severity_band);
        if band != SeverityBand::Unknown {
            return band;
        }
        match self
            .database_severity
            .as_deref()
            .map(str::to_ascii_uppercase)
            .as_deref()
        {
            Some("CRITICAL") => SeverityBand::Critical,
            Some("HIGH") => SeverityBand::High,
            Some("MODERATE" | "MEDIUM") => SeverityBand::Medium,
            Some("LOW") => SeverityBand::Low,
            _ => SeverityBand::Unknown,
        }
    }
}

impl Vulnerability {
    /// The lowest version above `version` that an `ECOSYSTEM` range of the
    /// Maven package `name` (`groupId:artifactId`) names as fixed, or
    /// `None` when the record names none. A dependency on another release
    /// line than the fix still gets the nearest higher fix.
    pub fn fixed_version(&self, name: &str, version: &str) -> Option<String> {
        let current = rv_maven_types::Version::parse(version).ok()?;
        (self.affected.iter())
            .filter(|affected| {
                affected.package.ecosystem.eq_ignore_ascii_case("Maven")
                    && affected.package.name == name
            })
            .flat_map(|affected| &affected.ranges)
            .filter(|range| range.type_.eq_ignore_ascii_case("ECOSYSTEM"))
            .flat_map(|range| &range.events)
            .filter_map(|event| event.fixed.as_deref())
            .filter_map(|fixed| rv_maven_types::Version::parse(fixed).ok())
            .filter(|fixed| *fixed > current)
            .min()
            .map(|fixed| fixed.as_str().to_string())
    }
}

/// Scores the vector's base metrics only: CVSS 4 folds threat and
/// environmental metrics into its score, and raeva reports the base score.
fn base_score<V: std::str::FromStr>(vector: &str, score: impl Fn(V) -> f64) -> Option<f32> {
    const BASE_METRICS: &[&str] = &[
        "AV", "AC", "PR", "UI", "S", "C", "I", "A", "AT", "VC", "VI", "VA", "SC", "SI", "SA",
    ];
    let mut parts = vector.split('/');
    let prefix = parts.next().unwrap_or_default();
    let base = parts.filter(|part| BASE_METRICS.contains(&part.split(':').next().unwrap_or("")));
    let vector = std::iter::once(prefix)
        .chain(base)
        .collect::<Vec<_>>()
        .join("/")
        .parse()
        .ok()?;
    Some(score(vector) as f32)
}

fn cvss_v2_score(vector: &str) -> Option<f32> {
    let vector = vector
        .strip_prefix("CVSS:2.0/")
        .or_else(|| vector.strip_prefix("CVSS2#"))
        .unwrap_or(vector);
    const IMPACT: &[(char, f64)] = &[('N', 0.0), ('P', 0.275), ('C', 0.660)];
    let metrics: &[(&str, &[(char, f64)])] = &[
        ("AV", &[('L', 0.395), ('A', 0.646), ('N', 1.0)]),
        ("AC", &[('H', 0.35), ('M', 0.61), ('L', 0.71)]),
        ("Au", &[('M', 0.45), ('S', 0.56), ('N', 0.704)]),
        ("C", IMPACT),
        ("I", IMPACT),
        ("A", IMPACT),
    ];
    let mut values = [None; 6];
    for metric in vector.split('/') {
        let (name, value) = metric.split_once(':')?;
        let Some(index) = metrics.iter().position(|(known, _)| *known == name) else {
            continue;
        };
        let value = value.to_ascii_uppercase();
        let key = value.chars().next().filter(|_| value.len() == 1)?;
        let weight = metrics[index].1.iter().find(|(k, _)| *k == key)?.1;
        if values[index].replace(weight).is_some() {
            return None;
        }
    }
    let [av, ac, au, c, i, a] = values;
    let impact = 10.41 * (1.0 - (1.0 - c?) * (1.0 - i?) * (1.0 - a?));
    let exploitability = 20.0 * av? * ac? * au?;
    let impact_factor = if impact == 0.0 { 0.0 } else { 1.176 };
    let score = ((0.6 * impact + 0.4 * exploitability - 1.5) * impact_factor).clamp(0.0, 10.0);
    Some(((score * 10.0_f64) + 0.5).floor() as f32 / 10.0)
}

/// One entry of OSV `references`: a link about the vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Reference {
    /// OSV `references[].type`, such as `ADVISORY`, `FIX` or `WEB`.
    #[serde(rename = "type")]
    pub type_: String,
    /// OSV `references[].url`, as the record gives it.
    pub url: String,
}

/// One entry of OSV `affected`: a package and the versions of it the
/// vulnerability affects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Affected {
    /// OSV `affected[].package`.
    pub package: Package,
    /// OSV `affected[].ranges`.
    #[serde(default)]
    pub ranges: Vec<Range>,
    /// OSV `affected[].versions`: versions listed one by one.
    #[serde(default)]
    pub versions: Vec<String>,
}

/// OSV `affected[].package`: the package an [`Affected`] entry names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Package {
    /// OSV `affected[].package.name`, `groupId:artifactId` for Maven.
    pub name: String,
    /// OSV `affected[].package.ecosystem`, such as `Maven`.
    pub ecosystem: String,
    /// OSV `affected[].package.purl`, when the record gives one.
    #[serde(default)]
    pub purl: Option<String>,
}

/// One entry of OSV `affected[].ranges`: affected versions described by
/// events in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Range {
    /// OSV `ranges[].type`: `ECOSYSTEM`, `SEMVER` or `GIT`.
    #[serde(rename = "type")]
    pub type_: String,
    /// OSV `ranges[].events`.
    #[serde(default)]
    pub events: Vec<RangeEvent>,
}

/// One entry of OSV `ranges[].events`. OSV sets exactly one field per
/// event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RangeEvent {
    /// OSV `events[].introduced`: the first affected version.
    #[serde(default)]
    pub introduced: Option<String>,
    /// OSV `events[].fixed`: the first version no longer affected.
    #[serde(default)]
    pub fixed: Option<String>,
    /// OSV `events[].last_affected`: the last affected version.
    #[serde(default)]
    pub last_affected: Option<String>,
    /// OSV `events[].limit`: an upper bound on the range.
    #[serde(default)]
    pub limit: Option<String>,
}

/// The vulnerabilities found for one queried purl.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VulnResult {
    /// The purl that was queried.
    pub purl: String,
    /// What OSV lists for it, deduplicated by id.
    pub vulnerabilities: Vec<Vulnerability>,
}

#[cfg(test)]
mod tests {
    use super::{Severity, SeverityBand};

    fn severity(type_: &str, score: &str) -> Severity {
        Severity {
            type_: type_.to_string(),
            score: score.to_string(),
        }
    }

    #[test]
    fn fixed_version_is_the_nearest_fix_above_the_version() {
        let record: super::Vulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-1",
            "summary": "",
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [
                        {"introduced": "0"}, {"fixed": "2.12.7.1"},
                        {"introduced": "2.13.0"}, {"fixed": "2.13.4.2"},
                    ]}],
                },
                {
                    "package": {"ecosystem": "Maven", "name": "org.example:other"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0.1"}]}],
                },
                {
                    "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                    "ranges": [{"type": "GIT", "events": [{"fixed": "2.12.8"}]}],
                },
            ],
        }))
        .expect("record");
        let fixed = |version| record.fixed_version("org.example:lib", version);
        assert_eq!(fixed("2.12.1").as_deref(), Some("2.12.7.1"));
        assert_eq!(fixed("2.13.2").as_deref(), Some("2.13.4.2"));
        assert_eq!(fixed("2.13.4.2"), None);
        assert_eq!(
            record.fixed_version("org.example:other", "1.0").as_deref(),
            Some("1.0.1")
        );
        assert_eq!(record.fixed_version("org.example:none", "1.0"), None);
    }

    #[test]
    fn scores_and_bands() {
        use SeverityBand::{Critical, High, Low, Medium, Unknown};
        let cases = [
            ("CVSS_V3", "9.8", Some(9.8), Critical),
            ("CVSS_V3", "8.5", Some(8.5), High),
            ("CVSS_V3", "5.0", Some(5.0), Medium),
            ("CVSS_V3", "2.0", Some(2.0), Low),
            ("CVSS_V3", "not-a-score", None, Unknown),
            ("CVSS_V3", "NaN", None, Unknown),
            ("CVSS_V3", "inf", None, Unknown),
            ("CVSS_V3", "-0.1", None, Unknown),
            ("CVSS_V3", "10.1", None, Unknown),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                Some(8.8),
                High,
            ),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L",
                Some(4.6),
                Medium,
            ),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
                Some(1.8),
                Low,
            ),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                Some(0.0),
                SeverityBand::None,
            ),
            // OSV publishes this temporal metric for Log4Shell.
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H",
                Some(10.0),
                Critical,
            ),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/MAV:N",
                Some(9.8),
                Critical,
            ),
            (
                "CVSS_V4",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
                Some(9.3),
                Critical,
            ),
            // Threat and environmental metrics do not change the base score.
            (
                "CVSS_V4",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
                Some(9.3),
                Critical,
            ),
            (
                "CVSS_V4",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:N",
                Some(9.3),
                Critical,
            ),
            ("CVSS_V3", "0.0", Some(0.0), SeverityBand::None),
            ("CVSS_V2", "AV:N/AC:L/Au:N/C:P/I:P/A:P", Some(7.5), High),
            // CVSS 2 has no critical band.
            (
                "CVSS_V2",
                "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
                Some(10.0),
                High,
            ),
            ("CVSS_V2", "AV:N/AC:L/Au:N/C:P/I:P/A:P/AV:N", None, Unknown),
            ("CVSS_V3", "AV:N/AC:L/Au:N/C:P/I:P/A:P", None, Unknown),
            ("OTHER", "AV:N/AC:L/Au:N/C:P/I:P/A:P", None, Unknown),
        ];
        for (type_, score, value, band) in cases {
            let severity = severity(type_, score);
            assert_eq!(severity.score_value(), value, "{type_} {score}");
            assert_eq!(severity.severity_band(), band, "{type_} {score}");
        }
    }
}
