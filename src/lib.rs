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

use bitcoin::util::hash::Hash160;
use bitcoin::blockdata::opcodes::All as OpCodes;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::blockdata::transaction::SigHashType;

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

pub fn hash160(data: &Vec<u8>) -> Vec<u8> {
    let mut v = Vec::new();
    let h160 = Hash160::from_data(&data.as_slice());
    for i in 0..20 {
        v.push(h160[i]);
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




#[cfg(test)]
mod tests {
    use bitcoin::blockdata::transaction::SigHashType;
    use secp256k1::constants::MESSAGE_SIZE;
    use super::random_bytes;
    use super::{ generate_keypair, sign };
    use super::{ NullData, P2PKHScriptPubkey, P2PKHScriptSig };

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
        let p2pkh_spk_1 = P2PKHScriptPubkey::from_public_key(&pk);
        let script_pubkey = p2pkh_spk_1.to_script();
        let p2pkh_spk_2 = P2PKHScriptPubkey::from_script(&script_pubkey);
        assert_eq!(p2pkh_spk_1, p2pkh_spk_2);
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

}
