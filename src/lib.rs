extern crate num;
extern crate rand;
extern crate byteorder;
extern crate arrayvec;
extern crate crypto;
extern crate secp256k1;
extern crate bitcoin;
extern crate serde;
#[allow(unused_imports)]
#[macro_use] extern crate serde_derive;

use bitcoin::util::hash::{ Hash160, Sha256dHash };
use bitcoin::blockdata::opcodes::All as OpCodes;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::blockdata::transaction::TxIn as Input;
use bitcoin::blockdata::transaction::TxOut as Output;
use bitcoin::blockdata::transaction::TxOutRef as UnspentOutput;
use bitcoin::blockdata::transaction::Transaction;

use secp256k1::Secp256k1;
use secp256k1::{ Message, Signature };
use secp256k1::constants::MESSAGE_SIZE;
use secp256k1::key::{ SecretKey, PublicKey };
use rand::{ thread_rng, Rng };

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..len {
        v.push(0u8);
    }
    thread_rng().fill_bytes(&mut v);
    v
}

pub fn generate_ctx() -> Secp256k1 {
    let mut ctx = Secp256k1::new();
    let mut rng = thread_rng();
    ctx.randomize(&mut rng);
    ctx
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let ctx = generate_ctx();
    let mut rng = thread_rng();
    ctx.generate_keypair(&mut rng).unwrap()
}

pub fn sign(message: &Vec<u8>, secret_key: &SecretKey) -> Signature {
    if message.len() != MESSAGE_SIZE {
        panic!("invalid message length")
    }
    let msg = Message::from_slice(&message.as_slice()).unwrap();
    let ctx = generate_ctx();
    ctx.sign(&msg, secret_key).unwrap()
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct NullData {
    data: Vec<u8>,
}

impl NullData {
    pub fn new(data: &Vec<u8>) -> Self {
        if data.len() > 80 {
            panic!("data length over 80 bytes")    
        }
        Self { data: data.clone() }
    }
    
    pub fn to_script(&self) -> Script {
        ScriptBuilder::new()
            .push_opcode(OpCodes::OP_RETURN)
            .push_slice(self.data.as_slice())
            .into_script()
    }

    pub fn from_script(s: &Script) -> Self { 
        if !s.is_provably_unspendable() {
            panic!("spendable script")
        }
        
        let s_vec = s.clone().into_vec();
        let nulldata = s_vec[0].clone();
        if nulldata != OpCodes::OP_RETURN as u8 {
            panic!("invalid op-code")
        }
       
        let op_pushbyte = s_vec[1].clone();
        if op_pushbyte < OpCodes::OP_PUSHBYTES_0 as u8 ||
            op_pushbyte > OpCodes::OP_PUSHBYTES_75 as u8
        {
            panic!("invalid op-code: {}", op_pushbyte)
        }
        
        let data_slice = &s_vec[2..];
        if data_slice.len() != op_pushbyte as usize {
            panic!("invalid data length")
        }
       
        let mut data = Vec::new();
        data.extend_from_slice(data_slice);
        
        Self::new(&data)
    }
}

pub fn sha256(data: &Vec<u8>) -> Vec<u8> {
    let mut v = Vec::new();
    let digest = Sha256dHash::from_data(&data.as_slice());
    for i in 0..20 {
        v.push(digest[i]);
    }
    v
}

pub fn hash160(data: &Vec<u8>) -> Vec<u8> {
    let mut v = Vec::new();
    let digest = Hash160::from_data(&data.as_slice());
    for i in 0..20 {
        v.push(digest[i]);
    }
    v
}

pub fn pkhash(public_key: &PublicKey) -> Vec<u8> {
    let ctx = generate_ctx();
    let pk_bin = public_key.serialize_vec(&ctx, true).to_vec();
    hash160(&pk_bin)
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct P2PKHScriptPubkey {
    public_key_hash: Vec<u8>,
}

impl P2PKHScriptPubkey {
    pub fn new(public_key_hash: &Vec<u8>) -> Self {
        if public_key_hash.len() != 20 {
            panic!("invalid hash len")
        }
        Self { public_key_hash: public_key_hash.clone() }
    }
   
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let public_key_hash = pkhash(public_key);
         Self::new(&public_key_hash)
    }
    
    pub fn to_script(&self) -> Script {
        ScriptBuilder::new()
            .push_opcode(OpCodes::OP_DUP)
            .push_opcode(OpCodes::OP_HASH160)
            .push_slice(self.public_key_hash.as_slice())
            .push_opcode(OpCodes::OP_EQUALVERIFY)
            .push_opcode(OpCodes::OP_CHECKSIG)
            .into_script()
    }

    pub fn from_script(s: &Script) -> Self { 
        if s.is_provably_unspendable() {
            panic!("unspendable script")
        }
        
        let s_vec = s.clone().into_vec();

        if s_vec.len() != 25 {
            panic!("invalid script length")
        }

        let op_dup = s_vec[0].clone();
        if op_dup != OpCodes::OP_DUP as u8 {
            panic!("invalid op-code")
        }

        let op_hash160 = s_vec[1].clone();
        if op_hash160 != OpCodes::OP_HASH160 as u8 {
            panic!("invalid op-code")
        }

        let op_pushbytes = s_vec[2].clone();
        if op_pushbytes != OpCodes::OP_PUSHBYTES_20 as u8 {
            panic!("invalid op-code")
        }
        
        let hash_slice = &s_vec[3..23];
        if hash_slice.len() != 20 {
            panic!("invalid hash length")
        }

        let op_equalverify = s_vec[23].clone();
        if op_equalverify != OpCodes::OP_EQUALVERIFY as u8 {
            panic!("invalid op-code")
        }

        let op_checksig = s_vec[24].clone();
        if op_checksig != OpCodes::OP_CHECKSIG as u8 {
            panic!("invalid op-code")
        }

        Self { public_key_hash: hash_slice.to_vec() }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct P2PKHScriptSig {
    public_key: PublicKey,
    signature: Signature,
    sighash_type: SigHashType,
}

impl P2PKHScriptSig {
    pub fn new(
        public_key: &PublicKey,
        signature: &Signature,
        sighash_type: SigHashType,
    ) -> Self {
        Self {
            public_key: public_key.clone(),
            signature: signature.clone(),
            sighash_type: sighash_type,
        }
    }
    
    pub fn to_script(&self) -> Script {
        let ctx = generate_ctx();
        let pk_bin = self.public_key.serialize_vec(&ctx, true).to_vec();
        let mut sig_bin = self.signature.serialize_der(&ctx);
        sig_bin.push(self.sighash_type as u8);
        sig_bin.push(self.sighash_type as u8);
        ScriptBuilder::new()
            .push_slice(sig_bin.as_slice())
            .push_slice(pk_bin.as_slice())
            .into_script()
    }

    pub fn from_script(s: &Script) -> Self { 
        if s.is_provably_unspendable() {
            panic!("unspendable script")
        }
        
        let s_vec = s.clone().into_vec();

        let s_vec_len = s_vec.len();
        if s_vec_len < 106 || s_vec_len > 108  {
            panic!("invalid script length")
        }

        let op_pushbytes_sig = s_vec[0];
        let op_pushbytes_sig_u8 = op_pushbytes_sig as u8;
        if op_pushbytes_sig_u8 < 71 || op_pushbytes_sig_u8 > 73 {
            panic!("invalid op-code")
        }

        let data = s_vec[1..op_pushbytes_sig_u8 as usize].to_vec();
        let data_len = data.len();
        let sig_bin = data[0..data_len-1].to_vec();

        let sighash_type = SigHashType::from_u32(s_vec[data[data_len-1] as usize] as u32);
        

        let op_pushbytes_pk = s_vec[(op_pushbytes_sig_u8+1) as usize];
        if op_pushbytes_pk != OpCodes::OP_PUSHBYTES_33 as u8 {
            panic!("invalid op-code")
        }

        let pk_bin_from = (op_pushbytes_sig_u8+2) as usize;
        let pk_bin_to = (pk_bin_from + 33) as usize;
        let pk_bin = s_vec[pk_bin_from..pk_bin_to].to_vec();

        let ctx = generate_ctx();
        let public_key = PublicKey::from_slice(&ctx, &pk_bin.as_slice()).unwrap();
        let signature = Signature::from_der(&ctx, &sig_bin.as_slice()).unwrap();

        Self {
            public_key: public_key,
            signature: signature,
            sighash_type: sighash_type,
        }
    }
}


#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct MultisigScriptPubkey {
    public_keys: Vec<Vec<u8>>,
    threshold: u32,
}

impl MultisigScriptPubkey {
    pub fn new(public_keys: &Vec<Vec<u8>>, threshold: u32) -> Self {
        let public_keys_len = public_keys.len() as u32;

        for pk_bin in public_keys {
            if pk_bin.clone().len() != 33 {
                panic!("invalid compressed public key lenght")
            }
        }

        if threshold > public_keys_len as u32 {
            panic!("invalid threshold")
        }
        if threshold == 0 || threshold > 16 {
            panic!("invalid threshold")
        }
        Self {
            public_keys: public_keys.clone(),
            threshold: threshold,
        }
    }
    
    pub fn to_script(&self) -> Script {
        let public_keys_len = self.public_keys.len();

        let m_opcode_u32 = ((OpCodes::OP_PUSHNUM_1 as u8) as u32) + self.threshold - 1;
        let m_opcode = OpCodes::from(m_opcode_u32 as u8);
        let n_opcode_u32 = ((OpCodes::OP_PUSHNUM_1 as u8) as u32) + (public_keys_len as u32) - 1;
        let n_opcode = OpCodes::from(n_opcode_u32 as u8);

        let mut script = ScriptBuilder::new().push_opcode(m_opcode);
        
        for pk in self.public_keys.clone() {
            script = script.clone().push_slice(&pk.as_slice());
        }
        
        script.push_opcode(n_opcode)
            .push_opcode(OpCodes::OP_CHECKMULTISIG)
            .into_script()
    }

    pub fn from_script(s: &Script) -> Self { 
        if s.is_provably_unspendable() {
            panic!("unspendable script")
        }
        
        let s_vec = s.clone().into_vec();

        let s_vec_len = s_vec.len();
        // min: op_pushnum_1 op_pushbytes_33 <pubkey> op_pushnum_1 op_checkmultisig
        //      which is 39 bytes
        // max: op_pushnum_16 (op_pushbytes_33 <pubkey>)*16 op_pushnum_x op_checkmultisig
        //      which is 531 bytes
        if s_vec_len < 5 || s_vec_len > 531 {
            panic!("invalid script length")
        }

        let op_m = s_vec[0].clone();
        if op_m < OpCodes::OP_PUSHNUM_1 as u8 ||
            op_m > OpCodes::OP_PUSHNUM_16 as u8
        {
            panic!("invalid op-code")
        }

        let threshold = ((op_m as u8) - (OpCodes::OP_PUSHNUM_1 as u8) + 1) as u32;

        let op_n = s_vec[s_vec_len-2].clone();
        if op_n < OpCodes::OP_PUSHNUM_1 as u8 ||
            op_n > OpCodes::OP_PUSHNUM_16 as u8
        {
            panic!("invalid op-code")
        }

        let length = ((op_n as u8) - (OpCodes::OP_PUSHNUM_1 as u8) + 1) as u32;

        if threshold > length {
            panic!("invalid thresold")
        }

        if s_vec_len != (3 + length*34) as usize {
            panic!("invalid length")
        }

        let op_checkmultisig = s_vec[s_vec_len-1].clone();
        if op_checkmultisig != OpCodes::OP_CHECKMULTISIG as u8 {
            panic!("invalid op-code")
        }

        let mut public_keys: Vec<Vec<u8>> = Vec::new();

        let pks_bin = s_vec[1..(length*34+1) as usize].to_vec();

        for i in 0..(length as usize) {
            let start = i*34;
            let stop = start + 34;
            let data = pks_bin[start..stop].to_vec();
            let op_pushbytes = data[0];
            if op_pushbytes != OpCodes::OP_PUSHBYTES_33 as u8 {
                panic!("invalid op-code")
            }
            let pk_bin = data[1..34].to_vec();
            public_keys.push(pk_bin)
        }

        Self {
            public_keys: public_keys,
            threshold: threshold,
        }
    }
}


#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct MultisigScriptSig {
    signatures: Vec<Vec<u8>>,
}

impl MultisigScriptSig {
    pub fn new(signatures: &Vec<Vec<u8>>) -> Self {
        for sig_bin in signatures.clone() {
            if sig_bin.len() < 70 || sig_bin.len() > 72 {
                panic!("invalid signature length")    
            }
        }
        Self {
            signatures: signatures.clone(),
        }
    }
    
    pub fn to_script(&self) -> Script {
        let mut script = ScriptBuilder::new()
            .push_opcode(OpCodes::OP_PUSHBYTES_0);
        
        for sig_bin in self.signatures.clone() {
            script = script.clone().push_slice(&sig_bin.as_slice());
        }
        
        script.into_script()
    }

    pub fn from_script(s: &Script) -> Self {
        if s.is_provably_unspendable() {
            panic!("unspendable script")
        }
        
        let s_vec = s.clone().into_vec();

        let s_vec_len = s_vec.len();
        // min: op_0 op_pushbytes_70 <sig>
        //      which is 72 bytes
        // max: op_0 (op_pushbytes_72 <sig>)*16
        //      which is 1153 bytes
        if s_vec_len < 72 || s_vec_len > 1153 {
            panic!("invalid script length")
        }

        let op_0 = s_vec[0].clone();
        if op_0 != OpCodes::OP_PUSHBYTES_0 as u8 {
            panic!("invalid op-code")
        }

        let mut signatures: Vec<Vec<u8>> = Vec::new();

        let sigs_bin = s_vec[1..].to_vec();
        let sigs_bin_len = sigs_bin.len();

        let mut idx = 0;

        while idx + 71 <= sigs_bin_len {
            let op_pushbytes = sigs_bin[idx];
            if op_pushbytes < OpCodes::OP_PUSHBYTES_70 as u8 ||
                op_pushbytes > OpCodes::OP_PUSHBYTES_72 as u8
            {
                panic!("invalid op-code")
            }

            let op_pushbytes_usize = op_pushbytes as usize;
        
            let sig_bin = sigs_bin[idx+1..idx+op_pushbytes_usize+1].to_vec();
            signatures.push(sig_bin);

            idx = idx + op_pushbytes_usize + 1;
        }

        Self {
            signatures: signatures,
        }
    }
}


pub const PREFIX: &str = "YBC";
pub const VERSION: &str = "0.0.1";


/*
    deposit transaction:
        note (nulldata output):
            nulldata: 80 bytes
                prefix: 3 bytes
                version: 3 bytes
                sidechain: 3 bytes
                sidechain_version: 3 bytes
                threshold: 4 bytes
                length: 4 bytes
                public_keys_hash: 20 bytes
                activation_time: 4 bytes
                expiration_time: 4 bytes
                coinbase: 4 bytes
                amount: 4 bytes
                data_length: 4 bytes
                data_hash: 20 bytes
            coinbase: varint
        fund (multisig output):
            script_sig: multisig script_pubkey
            amount: varint
        change (multisig output):
            script_sig: multisig script_pubkey
            amount: varint
        fee: varint
*/

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Note {
    sidechain: String,
    version: String,
    wallet: MultisigScriptPubkey,
    unspent_outputs: Vec<UnspentOutput>,
    activation_time: u32,
    expiration_time: u32,
    coinbase: u32,
    amount: u32,
    data_hash: Sha256dHash,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct P2PKHOutput {}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct P2PKHInput {}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct MultiSigOutput {}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct MultiSigInput {}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct DepositTransaction {
    note: Note,
    unspent_outputs: Vec<UnspentOutput>,
    change: MultiSigOutput,
    fee: u32,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct WithdrawTransaction {}


pub struct Store {}


pub struct Server {}


pub struct Client {}


#[cfg(test)]
mod tests {
    use bitcoin::blockdata::opcodes::All as OpCodes;
    use bitcoin::blockdata::script::Script;
    use bitcoin::blockdata::transaction::SigHashType;
    use secp256k1::constants::MESSAGE_SIZE;
    use super::random_bytes;
    use super::{ generate_ctx, generate_keypair, sign };
    use super::NullData;
    use super::{ P2PKHScriptPubkey, P2PKHScriptSig };
    use super::{ MultisigScriptPubkey, MultisigScriptSig };

    #[test]
    fn nulldata_succ() {
        let data = "blablabla".to_string();
        let nulldata_1 = NullData::new(&data.into_bytes());
        let script = nulldata_1.to_script();
        let nulldata_2 = NullData::from_script(&script);
        assert_eq!(nulldata_1, nulldata_2);
    }
    
    #[test]
    fn p2pkh_script_pubkey_succ() {
        let (_, pk) = generate_keypair();
        let p2pkh_sp_1 = P2PKHScriptPubkey::from_public_key(&pk);
        let script_pubkey = p2pkh_sp_1.to_script();
        let p2pkh_sp_2 = P2PKHScriptPubkey::from_script(&script_pubkey);
        assert_eq!(p2pkh_sp_1, p2pkh_sp_2);
    }

    #[test]
    fn p2pkh_script_sig_succ() {
        let (sk, pk) = generate_keypair();
        let v = random_bytes(MESSAGE_SIZE);
        let sig = sign(&v, &sk);
        let p2pkh_ss_1 = P2PKHScriptSig::new(&pk, &sig, SigHashType::All);
        let script = p2pkh_ss_1.to_script();
        let p2pkh_ss_2 = P2PKHScriptSig::from_script(&script);
        assert_eq!(p2pkh_ss_1, p2pkh_ss_2);
    }

    #[test]
    fn multisig_pubkey_succ() {
        let mut public_keys: Vec<Vec<u8>> = Vec::new();
        let ctx = generate_ctx();
        for _ in 0..10 {
            let (_, pk) = generate_keypair();
            let pk_bin = pk.serialize_vec(&ctx, true).to_vec();
            public_keys.push(pk_bin);
        }
        let threshold = 10;
        let multisig_sp_1 = MultisigScriptPubkey::new(
            &public_keys,
            threshold,
        );
        let script = multisig_sp_1.to_script();
        let multisig_sp_2 = MultisigScriptPubkey::from_script(&script);
        assert_eq!(multisig_sp_1, multisig_sp_2)
    }

    #[test]
    #[should_panic]
    fn multisig_pubkey_invalid_pubkey_fail() {
        let mut public_keys: Vec<Vec<u8>> = Vec::new();
        let ctx = generate_ctx();
        for _ in 0..10 {
            let (_, pk) = generate_keypair();
            let pk_bin = pk.serialize_vec(&ctx, true).to_vec();
            public_keys.push(pk_bin);
        }
        public_keys.push(random_bytes(34));
        let threshold = 6;
        MultisigScriptPubkey::new(
            &public_keys,
            threshold,
        );
    }

    #[test]
    #[should_panic]
    fn multisig_pubkey_threshold_zero_fail() {
        let mut public_keys: Vec<Vec<u8>> = Vec::new();
        let ctx = generate_ctx();
        for _ in 0..10 {
            let (_, pk) = generate_keypair();
            let pk_bin = pk.serialize_vec(&ctx, true).to_vec();
            public_keys.push(pk_bin);
        }
        let threshold = 0;
        MultisigScriptPubkey::new(
            &public_keys,
            threshold,
        );
    }

    #[test]
    #[should_panic]
    fn multisig_pubkey_threshold_overflow_fail() {
        let mut public_keys: Vec<Vec<u8>> = Vec::new();
        let ctx = generate_ctx();
        for _ in 0..10 {
            let (_, pk) = generate_keypair();
            let pk_bin = pk.serialize_vec(&ctx, true).to_vec();
            public_keys.push(pk_bin);
        }
        let threshold = 11;
        MultisigScriptPubkey::new(
            &public_keys,
            threshold,
        );
    }

    #[test]
    #[should_panic]
    fn multisig_pubkey_invalid_lenght_fail() {
        let mut public_keys: Vec<Vec<u8>> = Vec::new();
        let ctx = generate_ctx();
        for _ in 0..10 {
            let (_, pk) = generate_keypair();
            let pk_bin = pk.serialize_vec(&ctx, true).to_vec();
            public_keys.push(pk_bin);
        }
        let threshold = 10;
        let multisig_sp_1 = MultisigScriptPubkey::new(
            &public_keys,
            threshold,
        );
        let mut script = multisig_sp_1.to_script();
        let mut script_vec = script.into_vec();
        let script_vec_len = script_vec.clone().len();
        script_vec[script_vec_len-2] = OpCodes::OP_PUSHNUM_11 as u8;
        script = Script::from(script_vec);
        MultisigScriptPubkey::from_script(&script);
    }

    #[test]
    fn multisig_sig_succ() {
        let mut signatures: Vec<Vec<u8>> = Vec::new();
        for _ in 0..10 {
            signatures.push(random_bytes(72));
        }
        let multisig_ss_1 = MultisigScriptSig::new(&signatures);
        let script = multisig_ss_1.to_script();
        let multisig_ss_2 = MultisigScriptSig::from_script(&script);
        assert_eq!(multisig_ss_1, multisig_ss_2);
    }

    #[test]
    #[should_panic]
    fn multisig_sig_invalid_signature_fail() {
        let mut signatures: Vec<Vec<u8>> = Vec::new();
        for _ in 0..10 {
            signatures.push(random_bytes(72));
        }
        signatures.push(random_bytes(69));
        MultisigScriptSig::new(&signatures);
    }

    #[test]
    #[should_panic]
    fn multisig_sig_invalid_op_code_fail() {
        let mut signatures: Vec<Vec<u8>> = Vec::new();
        for _ in 0..10 {
            signatures.push(random_bytes(72));
        }
        MultisigScriptSig::new(&signatures);
        let multisig_ss_1 = MultisigScriptSig::new(&signatures);
        let mut script = multisig_ss_1.to_script();
        let mut script_vec = script.into_vec();
        script_vec[0] = OpCodes::OP_PUSHBYTES_1 as u8;
        script = Script::from(script_vec);
        MultisigScriptSig::from_script(&script);
    }
}
