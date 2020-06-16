//! A simple struct for dealing with derivation paths as defined by BIP32, BIP44 and BIP49 of the
//! Bitcoin protocol. This crate provides interfaces for dealing with hardened vs normal child
//! indexes, as well as display and parsing derivation paths from strings
//!
//! # Example
//!
//! ```
//! # use derivation_path::{ChildIndex, DerivationPath, DerivationPathType};
//! let path = DerivationPath::bip44(0, 1, 0, 1).unwrap();
//! assert_eq!(&path.to_string(), "m/44'/0'/1'/0/1");
//! assert_eq!(path.path()[2], ChildIndex::Hardened(1));
//!
//! let path: DerivationPath = "m/49'/0'/0'/1/0".parse().unwrap();
//! assert_eq!(path.path()[4], ChildIndex::Normal(0));
//! assert_eq!(path.path_type(), DerivationPathType::BIP49);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, string::String};

use core::fmt;
use core::str::FromStr;
use failure::Fail;

/// Errors when building a [DerivationPath]
#[derive(Fail, Debug, Clone)]
pub enum DerivationPathError {
    #[fail(display = "path too long")]
    PathTooLong,
    #[fail(display = "invalid child index: {}", _0)]
    InvalidChildIndex(ChildIndexError),
}

/// Errors when parsing a [DerivationPath] from a [str]
#[derive(Fail, Debug, Clone)]
pub enum DerivationPathParseError {
    #[fail(display = "empty")]
    Empty,
    #[fail(display = "invalid prefix: {}", _0)]
    InvalidPrefix(String),
    #[fail(display = "invalid child index: {}", _0)]
    InvalidChildIndex(ChildIndexParseError),
}

/// A list of [ChildIndex] items
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationPath(Box<[ChildIndex]>);

/// [DerivationPath] specifications as defined by BIP's
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DerivationPathType {
    None,
    BIP32,
    BIP44,
    BIP49,
}

impl DerivationPath {
    /// Build a [DerivationPath] from a list of [ChildIndex] items
    #[inline]
    pub fn new<P>(path: P) -> Self
    where
        P: Into<Box<[ChildIndex]>>,
    {
        DerivationPath(path.into())
    }

    /// Build a BIP32 style [DerivationPath]. This will fail if the length of the path is greater
    /// than 255 items
    pub fn bip32<P>(path: P) -> Result<Self, DerivationPathError>
    where
        P: Into<Box<[ChildIndex]>>,
    {
        let path = path.into();
        if path.len() > 255 {
            return Err(DerivationPathError::PathTooLong);
        }
        Ok(Self::new(path))
    }

    /// Build a BIP44 style [DerivationPath]: `m/44'/coin'/account'/change/address`
    #[inline]
    pub fn bip44(
        coin: u32,
        account: u32,
        change: u32,
        address: u32,
    ) -> Result<Self, DerivationPathError> {
        Self::bip4x(44, coin, account, change, address)
    }

    /// Build a BIP49 style [DerivationPath]: `m/49'/coin'/account'/change/address`
    #[inline]
    pub fn bip49(
        coin: u32,
        account: u32,
        change: u32,
        address: u32,
    ) -> Result<Self, DerivationPathError> {
        Self::bip4x(49, coin, account, change, address)
    }

    #[inline]
    fn bip4x(
        purpose: u32,
        coin: u32,
        account: u32,
        change: u32,
        address: u32,
    ) -> Result<Self, DerivationPathError> {
        Ok(Self::new(
            [
                ChildIndex::hardened(purpose)?,
                ChildIndex::hardened(coin)?,
                ChildIndex::hardened(account)?,
                ChildIndex::normal(change)?,
                ChildIndex::normal(address)?,
            ]
            .as_ref(),
        ))
    }

    /// Get a reference to the list of [ChildIndex] items
    #[inline]
    pub fn path(&self) -> &[ChildIndex] {
        self.0.as_ref()
    }

    /// Get the [DerivationPathType]. This will check the "purpose" index in BIP44/49 style
    /// derivation paths or otherwise return BIP32 if the length is less than 255
    pub fn path_type(&self) -> DerivationPathType {
        let path = self.path();
        let len = path.len();
        if len == 5
            && path[1].is_hardened()
            && path[2].is_hardened()
            && path[3].is_normal()
            && path[4].is_normal()
        {
            match path[0] {
                ChildIndex::Hardened(44) => DerivationPathType::BIP44,
                ChildIndex::Hardened(49) => DerivationPathType::BIP49,
                _ => DerivationPathType::BIP32,
            }
        } else if len < 256 {
            DerivationPathType::BIP32
        } else {
            DerivationPathType::None
        }
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        for index in self.path() {
            f.write_str("/")?;
            fmt::Display::fmt(index, f)?;
        }
        Ok(())
    }
}

impl FromStr for DerivationPath {
    type Err = DerivationPathParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(DerivationPathParseError::Empty);
        }
        let mut parts = s.split('/');
        match parts.next().unwrap() {
            "m" => (),
            prefix => return Err(DerivationPathParseError::InvalidPrefix(prefix.to_owned())),
        }
        let path = parts
            .map(|part| ChildIndex::from_str(part).map_err(|e| e.into()))
            .collect::<Result<Box<[ChildIndex]>, DerivationPathParseError>>()?;
        Ok(DerivationPath::new(path))
    }
}

/// An index in a [DerivationPath]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ChildIndex {
    Normal(u32),
    Hardened(u32),
}

/// Errors when parsing a [ChildIndex] from a [str]
#[derive(Fail, Debug, Clone)]
pub enum ChildIndexParseError {
    #[fail(display = "could not parse child index: {}", _0)]
    ParseIntError(core::num::ParseIntError),
    #[fail(display = "invalid child index: {}", _0)]
    ChildIndexError(ChildIndexError),
}

/// Errors when building a [ChildIndex]
#[derive(Fail, Debug, Clone)]
pub enum ChildIndexError {
    #[fail(display = "number too large: {}", _0)]
    NumberTooLarge(u32),
}

impl ChildIndex {
    /// Create a [ChildIndex::Hardened] instance from a [u32]. This will fail if `num` is not
    /// in `[0, 2^31 - 1]`
    pub fn hardened(num: u32) -> Result<Self, ChildIndexError> {
        Ok(Self::Hardened(Self::check_size(num)?))
    }

    /// Create a [ChildIndex::Normal] instance from a [u32]. This will fail if `num` is not
    /// in `[0, 2^31 - 1]`
    pub fn normal(num: u32) -> Result<Self, ChildIndexError> {
        Ok(Self::Normal(Self::check_size(num)?))
    }

    fn check_size(num: u32) -> Result<u32, ChildIndexError> {
        if num & (1 << 31) == 0 {
            Ok(num)
        } else {
            Err(ChildIndexError::NumberTooLarge(num))
        }
    }

    /// Convert [ChildIndex] to a [u32]
    #[inline]
    pub fn to_u32(self) -> u32 {
        match self {
            ChildIndex::Hardened(index) => index,
            ChildIndex::Normal(index) => index,
        }
    }

    /// Check if the [ChildIndex] is "hardened"
    #[inline]
    pub fn is_hardened(self) -> bool {
        match self {
            Self::Hardened(_) => true,
            _ => false,
        }
    }

    /// Check if the [ChildIndex] is "normal"
    #[inline]
    pub fn is_normal(self) -> bool {
        match self {
            Self::Normal(_) => true,
            _ => false,
        }
    }
}

impl fmt::Display for ChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.to_u32(), f)?;
        if self.is_hardened() {
            f.write_str("'")?;
        }
        Ok(())
    }
}

impl FromStr for ChildIndex {
    type Err = ChildIndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        Ok(match chars.next_back() {
            Some('\'') => Self::hardened(u32::from_str(chars.as_str())?)?,
            _ => Self::normal(u32::from_str(s)?)?,
        })
    }
}

impl From<core::num::ParseIntError> for ChildIndexParseError {
    fn from(err: core::num::ParseIntError) -> Self {
        Self::ParseIntError(err)
    }
}

impl From<ChildIndexError> for ChildIndexParseError {
    fn from(err: ChildIndexError) -> Self {
        Self::ChildIndexError(err)
    }
}

impl From<ChildIndexParseError> for DerivationPathParseError {
    fn from(err: ChildIndexParseError) -> Self {
        Self::InvalidChildIndex(err)
    }
}

impl From<ChildIndexError> for DerivationPathError {
    fn from(err: ChildIndexError) -> Self {
        Self::InvalidChildIndex(err)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString, vec};

    #[test]
    fn child_index_is_normal() {
        assert!(ChildIndex::Hardened(0).is_hardened());
        assert!(!ChildIndex::Normal(0).is_hardened());
    }

    #[test]
    fn child_index_is_hardened() {
        assert!(!ChildIndex::Hardened(0).is_normal());
        assert!(ChildIndex::Normal(0).is_normal());
    }

    #[test]
    fn child_index_range() {
        assert!(ChildIndex::normal(0).is_ok());
        assert!(ChildIndex::normal(1).is_ok());
        assert!(ChildIndex::normal(100).is_ok());
        assert!(ChildIndex::normal(1 << 31).is_err());

        assert!(ChildIndex::hardened(0).is_ok());
        assert!(ChildIndex::hardened(1 << 31).is_err());
    }

    #[test]
    fn child_index_to_u32() {
        assert_eq!(ChildIndex::Normal(0).to_u32(), 0);
        assert_eq!(ChildIndex::Normal(1).to_u32(), 1);
        assert_eq!(ChildIndex::Normal(100).to_u32(), 100);
        assert_eq!(ChildIndex::Hardened(0).to_u32(), 0);
        assert_eq!(ChildIndex::Hardened(1).to_u32(), 1);
    }

    #[test]
    fn child_index_to_string() {
        assert_eq!(&ChildIndex::Normal(0).to_string(), "0");
        assert_eq!(&ChildIndex::Normal(1).to_string(), "1");
        assert_eq!(&ChildIndex::Normal(100).to_string(), "100");
        assert_eq!(&ChildIndex::Hardened(0).to_string(), "0'");
        assert_eq!(&ChildIndex::Hardened(1).to_string(), "1'");
        assert_eq!(&ChildIndex::Hardened(100).to_string(), "100'");
    }

    #[test]
    fn child_index_from_str() {
        assert_eq!(ChildIndex::Normal(0), "0".parse().unwrap());
        assert_eq!(ChildIndex::Normal(1), "1".parse().unwrap());
        assert_eq!(ChildIndex::Normal(100), "100".parse().unwrap());
        assert_eq!(ChildIndex::Hardened(0), "0'".parse().unwrap());
        assert_eq!(ChildIndex::Hardened(1), "1'".parse().unwrap());
        assert_eq!(ChildIndex::Hardened(100), "100'".parse().unwrap());
        assert!(matches!(
            ChildIndex::from_str(""),
            Err(ChildIndexParseError::ParseIntError(_))
        ));
        assert!(matches!(
            ChildIndex::from_str("a"),
            Err(ChildIndexParseError::ParseIntError(_))
        ));
        assert!(matches!(
            ChildIndex::from_str("100 "),
            Err(ChildIndexParseError::ParseIntError(_))
        ));
        assert!(matches!(
            ChildIndex::from_str("99a"),
            Err(ChildIndexParseError::ParseIntError(_))
        ));
        assert!(matches!(
            ChildIndex::from_str("a10"),
            Err(ChildIndexParseError::ParseIntError(_))
        ));
        assert!(matches!(
            ChildIndex::from_str(" 10"),
            Err(ChildIndexParseError::ParseIntError(_))
        ));
        assert!(matches!(
            ChildIndex::from_str(&(1u32 << 31).to_string()),
            Err(ChildIndexParseError::ChildIndexError(_))
        ));
    }

    #[test]
    fn derivation_path_new() {
        let path = [
            ChildIndex::Normal(1),
            ChildIndex::Hardened(2),
            ChildIndex::Normal(3),
        ];
        assert_eq!(&path, DerivationPath::new(path.as_ref()).path());

        let path: [ChildIndex; 0] = [];
        assert_eq!(&path, DerivationPath::new(path.as_ref()).path());

        let path = vec![ChildIndex::Normal(0); 256];
        assert_eq!(path.as_slice(), DerivationPath::new(path.as_ref()).path());
    }

    #[test]
    fn derivation_bip32() {
        let path = [
            ChildIndex::Normal(1),
            ChildIndex::Hardened(2),
            ChildIndex::Normal(3),
        ];
        assert_eq!(&path, DerivationPath::bip32(path.as_ref()).unwrap().path());

        let path: [ChildIndex; 0] = [];
        assert_eq!(&path, DerivationPath::bip32(path.as_ref()).unwrap().path());

        let path = vec![ChildIndex::Normal(0); 256];
        assert!(matches!(
            DerivationPath::bip32(path.as_ref()),
            Err(DerivationPathError::PathTooLong)
        ));
    }

    #[test]
    fn derivation_bip44() {
        assert_eq!(
            DerivationPath::bip44(1, 2, 3, 4).unwrap().path(),
            &[
                ChildIndex::Hardened(44),
                ChildIndex::Hardened(1),
                ChildIndex::Hardened(2),
                ChildIndex::Normal(3),
                ChildIndex::Normal(4)
            ]
        );

        assert!(matches!(
            DerivationPath::bip44(1 << 31, 0, 0, 0),
            Err(DerivationPathError::InvalidChildIndex(_))
        ));
    }

    #[test]
    fn derivation_bip49() {
        assert_eq!(
            DerivationPath::bip49(1, 2, 3, 4).unwrap().path(),
            &[
                ChildIndex::Hardened(49),
                ChildIndex::Hardened(1),
                ChildIndex::Hardened(2),
                ChildIndex::Normal(3),
                ChildIndex::Normal(4)
            ]
        );

        assert!(matches!(
            DerivationPath::bip44(1 << 31, 0, 0, 0),
            Err(DerivationPathError::InvalidChildIndex(_))
        ));
    }

    #[test]
    fn derivation_path_type() {
        assert_eq!(
            DerivationPath::new(vec![
                ChildIndex::Normal(0),
                ChildIndex::Normal(0),
                ChildIndex::Normal(0)
            ])
            .path_type(),
            DerivationPathType::BIP32
        );
        assert_eq!(
            DerivationPath::new(vec![]).path_type(),
            DerivationPathType::BIP32
        );
        assert_eq!(
            DerivationPath::new(vec![
                ChildIndex::Hardened(44),
                ChildIndex::Hardened(0),
                ChildIndex::Hardened(0),
                ChildIndex::Normal(0),
                ChildIndex::Normal(0)
            ])
            .path_type(),
            DerivationPathType::BIP44
        );
        assert_eq!(
            DerivationPath::new(vec![
                ChildIndex::Hardened(44),
                ChildIndex::Hardened(0),
                ChildIndex::Hardened(0),
                ChildIndex::Normal(0),
            ])
            .path_type(),
            DerivationPathType::BIP32
        );
        assert_eq!(
            DerivationPath::new(vec![
                ChildIndex::Hardened(43),
                ChildIndex::Hardened(0),
                ChildIndex::Hardened(0),
                ChildIndex::Normal(0),
                ChildIndex::Normal(0)
            ])
            .path_type(),
            DerivationPathType::BIP32
        );
        assert_eq!(
            DerivationPath::new(vec![
                ChildIndex::Hardened(44),
                ChildIndex::Hardened(0),
                ChildIndex::Normal(0),
                ChildIndex::Normal(0),
                ChildIndex::Normal(0)
            ])
            .path_type(),
            DerivationPathType::BIP32
        );
        assert_eq!(
            DerivationPath::new(vec![
                ChildIndex::Hardened(49),
                ChildIndex::Hardened(0),
                ChildIndex::Hardened(0),
                ChildIndex::Normal(0),
                ChildIndex::Normal(0)
            ])
            .path_type(),
            DerivationPathType::BIP49
        );
        assert_eq!(
            DerivationPath::new(vec![ChildIndex::Normal(0); 256]).path_type(),
            DerivationPathType::None
        );
    }

    #[test]
    fn derivation_path_to_string() {
        assert_eq!(
            &DerivationPath::new(vec![
                ChildIndex::Hardened(1),
                ChildIndex::Hardened(2),
                ChildIndex::Normal(3),
                ChildIndex::Hardened(4)
            ])
            .to_string(),
            "m/1'/2'/3/4'"
        );
        assert_eq!(
            &DerivationPath::new(vec![
                ChildIndex::Hardened(1),
                ChildIndex::Hardened(2),
                ChildIndex::Hardened(4),
                ChildIndex::Normal(3),
            ])
            .to_string(),
            "m/1'/2'/4'/3"
        );
        assert_eq!(
            &DerivationPath::new(vec![
                ChildIndex::Normal(100),
                ChildIndex::Hardened(2),
                ChildIndex::Hardened(4),
                ChildIndex::Normal(3),
            ])
            .to_string(),
            "m/100/2'/4'/3"
        );
        assert_eq!(
            &DerivationPath::new(vec![ChildIndex::Normal(0),]).to_string(),
            "m/0"
        );
        assert_eq!(&DerivationPath::new(vec![]).to_string(), "m");
    }

    #[test]
    fn derivation_path_parsing() {
        assert_eq!(
            DerivationPath::new(vec![
                ChildIndex::Hardened(1),
                ChildIndex::Hardened(2),
                ChildIndex::Normal(3),
                ChildIndex::Hardened(4)
            ]),
            "m/1'/2'/3/4'".parse().unwrap()
        );
        assert_eq!(
            DerivationPath::new(vec![
                ChildIndex::Hardened(1),
                ChildIndex::Hardened(2),
                ChildIndex::Hardened(4),
                ChildIndex::Normal(3),
            ]),
            "m/1'/2'/4'/3".parse().unwrap()
        );
        assert_eq!(
            DerivationPath::new(vec![
                ChildIndex::Normal(100),
                ChildIndex::Hardened(2),
                ChildIndex::Hardened(4),
                ChildIndex::Normal(3),
            ]),
            "m/100/2'/4'/3".parse().unwrap()
        );
        assert_eq!(
            DerivationPath::new(vec![ChildIndex::Normal(0),]),
            "m/0".parse().unwrap()
        );
        assert_eq!(DerivationPath::new(vec![]), "m".parse().unwrap());

        assert!(matches!(
            DerivationPath::from_str(""),
            Err(DerivationPathParseError::Empty)
        ));
        assert!(matches!(
            DerivationPath::from_str("n/0"),
            Err(DerivationPathParseError::InvalidPrefix(_))
        ));
        assert!(matches!(
            DerivationPath::from_str("mn/0"),
            Err(DerivationPathParseError::InvalidPrefix(_))
        ));
        assert!(matches!(
            DerivationPath::from_str("m/0/"),
            Err(DerivationPathParseError::InvalidChildIndex(_))
        ));
        assert!(matches!(
            DerivationPath::from_str("m/0/a/1"),
            Err(DerivationPathParseError::InvalidChildIndex(_))
        ));
        assert!(matches!(
            DerivationPath::from_str("m/0///1"),
            Err(DerivationPathParseError::InvalidChildIndex(_))
        ));
        assert!(matches!(
            DerivationPath::from_str(&format!("m/0/{}/1", (1u32 << 31))),
            Err(DerivationPathParseError::InvalidChildIndex(_))
        ));
        assert!(matches!(
            DerivationPath::from_str("m|1"),
            Err(DerivationPathParseError::InvalidPrefix(_))
        ));
    }
}
