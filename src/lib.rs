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
use bitcoin::network::constants::Network;
use bitcoin::blockdata::constants::max_money;
use bitcoin::blockdata::opcodes::All as OpCodes;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::blockdata::transaction::TxOut as Output;

use secp256k1::Secp256k1;
use secp256k1::key::{ SecretKey, PublicKey };
use rand::thread_rng;

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let ctx = Secp256k1::new();
    let mut rng = thread_rng();
    ctx.generate_keypair(&mut rng).unwrap()
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

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct NullDataOutput {
    data: Vec<u8>,
    value: u64,
}

impl NullDataOutput {
    pub fn new(data: &Vec<u8>, value: u64) -> Self {
        if data.len() > 80 {
            panic!("data length over 80 bytes")    
        }
        if value > max_money(Network::Bitcoin) {
            panic!("invalid amount of value")
        }
        Self {
            data: data.clone(),
            value: value,
        }
    }
    
    pub fn to_output(&self) -> Output {
        let nulldata = NullData::new(&self.data);
        let script = nulldata.to_script();
        Output {
            value: self.value,
            script_pubkey: script,
        }
    }

    pub fn from_output(output: &Output) -> Self {
        let value = output.value;
        if value > max_money(Network::Bitcoin) {
            panic!("invalid amount of value")
        }
        let script = output.clone().script_pubkey;
        let nulldata = NullData::from_script(&script);
        let data = nulldata.data.clone();
        Self {
            data: data,
            value: value,
        }
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
    let mut ctx = Secp256k1::new();
    let mut rng = thread_rng();
    ctx.randomize(&mut rng);
    // NB: pk get compressed to 33 bytes
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
pub struct P2PKHOutput {
    public_key_hash: Vec<u8>,
    value: u64,
}

impl P2PKHOutput {
    pub fn new(public_key: &PublicKey, value: u64) -> Self {
        let public_key_hash = pkhash(public_key);
        if value > max_money(Network::Bitcoin) {
            panic!("invalid amount of value")
        }
        Self {
            public_key_hash: public_key_hash,
            value: value,
        }
    }
    
    pub fn to_output(&self) -> Output {
        let p2pkh_spk = P2PKHScriptPubkey::new(&self.public_key_hash);
        let script_pubkey = p2pkh_spk.to_script();
        Output {
            value: self.value,
            script_pubkey: script_pubkey,
        }
    }

    pub fn from_output(output: &Output) -> Self {
        let value = output.value;
        if value > max_money(Network::Bitcoin) {
            panic!("invalid amount of value")
        }
        let script_pubkey = output.clone().script_pubkey;
        let p2pkh_spk = P2PKHScriptPubkey::from_script(&script_pubkey);
        let public_key_hash = p2pkh_spk.public_key_hash;
        Self {
            public_key_hash: public_key_hash,
            value: value,
        }
    }
}










#[cfg(test)]
mod tests {
    use bitcoin::network::constants::Network;
    use bitcoin::blockdata::constants::max_money;
    use super::generate_keypair;
    use super::{ NullData, NullDataOutput };
    use super::{ P2PKHScriptPubkey, P2PKHOutput };

    #[test]
    fn nulldata_succ() {
        let data = "blablabla".to_string();
        let nulldata_1 = NullData::new(&data.into_bytes());
        let script = nulldata_1.to_script();
        let nulldata_2 = NullData::from_script(&script);
        assert_eq!(nulldata_1, nulldata_2);
    }

    #[test]
    #[should_panic]
    fn nulldata_too_much_data_fail() {
        let data = "blablablabalbalbalsdfdsfdsfdslfjhdsafsd\
                    jfdsfkadshfkjsaadfhsljfahslkfdjashldkfja\
                    shlfk".to_string();
        NullData::new(&data.into_bytes());
    }

    #[test]
    fn nulldata_output_succ() {
        let data = "blablabla".to_string();
        let data_bin = data.into_bytes();
        let satoshis = 100_000_000;
        let nulldata_output_1 = NullDataOutput::new(&data_bin, satoshis);
        let output = nulldata_output_1.to_output();
        let nulldata_output_2 = NullDataOutput::from_output(&output);
        assert_eq!(nulldata_output_1, nulldata_output_2);
    }

    #[test]
    #[should_panic]
    fn nulldata_output_too_much_satoshis_fail() {
        let data = "blablabla".to_string();
        let data_bin = data.into_bytes();
        let satoshis = max_money(Network::Bitcoin) + 1;
        NullDataOutput::new(&data_bin, satoshis);
    }
    
    #[test]
    fn p2pkh_succ() {
        let (_, pk) = generate_keypair();
        let p2pkh_spk_1 = P2PKHScriptPubkey::from_public_key(&pk);
        let script_pubkey = p2pkh_spk_1.to_script();
        let p2pkh_spk_2 = P2PKHScriptPubkey::from_script(&script_pubkey);
        assert_eq!(p2pkh_spk_1, p2pkh_spk_2);
    }

    #[test]
    fn p2pkh_output_succ() {
        let (_, pk) = generate_keypair();
        let value = 100_000_000;
        let p2pkh_output_1 = P2PKHOutput::new(&pk, value);
        let output = p2pkh_output_1.to_output();
        let p2pkh_output_2 = P2PKHOutput::from_output(&output);
        assert_eq!(p2pkh_output_1, p2pkh_output_2);
    }

    #[test]
    #[should_panic]
    fn p2pkh_output_fail() {
        assert!(false)
    }
}
