// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DIGIBYTE_KEY_IO_H
#define DIGIBYTE_KEY_IO_H

#include <chainparams.h>
#include <key.h>
#include <pubkey.h>
#include <script/standard.h>
#include <support/allocators/zeroafterfree.h>
#include <bech32.h>
#include <base58.h>
#include <script/script.h>

#include <string>

CKey DecodeSecret(const std::string& str);
std::string EncodeSecret(const CKey& key);

CExtKey DecodeExtKey(const std::string& str);
std::string EncodeExtKey(const CExtKey& extkey);
CExtPubKey DecodeExtPubKey(const std::string& str);
std::string EncodeExtPubKey(const CExtPubKey& extpubkey);

std::string EncodeDestination(const CTxDestination& dest, bool fBech32=false);
CTxDestination DecodeDestination(const std::string& str);
bool IsValidDestinationString(const std::string& str);
bool IsValidDestinationString(const std::string& str, const CChainParams& params);

/**
 * Base class for all base58-encoded data
 */
class CBase58Data
{
protected:
    //! the version byte(s)
    std::vector<unsigned char> vchVersion;

    //! the actually encoded data
    typedef std::vector<unsigned char, zero_after_free_allocator<unsigned char> > vector_uchar;
    vector_uchar vchData;
    bool fBech32;

    CBase58Data();
    void SetData(const std::vector<unsigned char> &vchVersionIn, const void* pdata, size_t nSize);
    void SetData(const std::vector<unsigned char> &vchVersionIn, const unsigned char *pbegin, const unsigned char *pend);

public:
    bool SetString(const char* psz, unsigned int nVersionBytes = 1);
    bool SetString(const std::string& str);
    std::string ToString() const;
    int CompareTo(const CBase58Data& b58) const;

    bool operator==(const CBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const CBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CBase58Data& b58) const { return CompareTo(b58) >  0; }

    bool IsBech32() const {return fBech32;}
};

/** base58-encoded Bitcoin addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 */
class CBitcoinAddress : public CBase58Data {
public:
    bool Set(const CKeyID &id, bool fBech32 = false);
    bool Set(const CScriptID &id, bool fBech32 = false);
    bool Set(const CKeyID256 &id, bool fBech32 = false);
    bool Set(const CScriptID256 &id, bool fBech32 = false);
    bool Set(const CKeyID &id, CChainParams::Base58Type prefix, bool fBech32 = false);
    bool Set(const CTxDestination &dest, bool fBech32 = false);

    bool IsValid() const;
    bool IsValid(const CChainParams &params) const;
    bool IsValid(CChainParams::Base58Type prefix) const;

    CBitcoinAddress() {}
    CBitcoinAddress(const CTxDestination &dest) { Set(dest); }
    CBitcoinAddress(const CTxDestination &dest, bool fBech32) { Set(dest, fBech32); }
    CBitcoinAddress(const std::string& strAddress) { SetString(strAddress); }
    CBitcoinAddress(const char* pszAddress) { SetString(pszAddress); }

    CTxDestination Get() const;
    CTxDestination GetStakeOnly() const;
    bool GetKeyID(CKeyID &keyID) const;
    bool GetKeyID(CKeyID256 &keyID) const;
    bool GetKeyID(CKeyID &keyID, CChainParams::Base58Type prefix) const;
    bool GetIndexKey(uint256 &hashBytes, int &type) const;
    bool IsScript() const;

    uint8_t getVersion()
    {
        // TODO: Fix for multibyte versions
        if (vchVersion.size() > 0)
            return vchVersion[0];
        return 0;
    }
    std::vector<uint8_t> &getVchVersion()
    {
        return vchVersion;
    }
    void setVersion(const std::vector<uint8_t> &version)
    {
        vchVersion = version;
        return;
    }
};

/**
 * A base58-encoded secret key
 */
class CBitcoinSecret : public CBase58Data
{
public:
    void SetKey(const CKey& vchSecret);
    CKey GetKey() const;
    bool IsValid() const;
    bool SetString(const char* pszSecret);
    bool SetString(const std::string& strSecret);

    CBitcoinSecret(const CKey& vchSecret) { SetKey(vchSecret); }
    CBitcoinSecret() {}
};

template<typename K, int Size, CChainParams::Base58Type Type> class CBitcoinExtKeyBase : public CBase58Data
{
public:
    void SetKey(const K &key) {
        unsigned char vch[Size];
        key.Encode(vch);
        SetData(Params().Base58Prefix(Type), vch, vch+Size);
    }

    int Set58(const char *base58)
    {
        std::vector<uint8_t> vchBytes;
        if (!DecodeBase58(base58, vchBytes))
            return 1;

        if (0 != memcmp(&vchBytes[0], &Params().Base58Prefix(Type)[0], 4))
            return 4;

        SetData(Params().Base58Prefix(Type), &vchBytes[4], &vchBytes[4]+Size);
        return 0;
    }

    K GetKey() {
        K ret;
        if (vchData.size() == Size) {
            // If base58 encoded data does not hold an ext key, return a !IsValid() key
            ret.Decode(vchData.data());
        }
        return ret;
    }

    CBitcoinExtKeyBase(const K &key) {
        SetKey(key);
    }

    CBitcoinExtKeyBase(const std::string& strBase58c) {
        SetString(strBase58c.c_str(), Params().Base58Prefix(Type).size());
    }

    CBitcoinExtKeyBase() {}
};

typedef CBitcoinExtKeyBase<CExtKey, BIP32_EXTKEY_SIZE, CChainParams::EXT_SECRET_KEY> CBitcoinExtKey;
typedef CBitcoinExtKeyBase<CExtPubKey, BIP32_EXTKEY_SIZE, CChainParams::EXT_PUBLIC_KEY> CBitcoinExtPubKey;

#endif // DIGIBYTE_KEY_IO_H