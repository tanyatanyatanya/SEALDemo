#include "seal/seal.h" 
#include "/home/tanya/SEAL/native/examples/examples.h"   //安装SEAL库后，导入其路径下的文件SEAL/native/examples/examples.h
#include <iostream> 
#include<stdlib.h>
#include<time.h>
#define random(x) (rand()%x)

using namespace std; 
using namespace seal; 

int main() 
{ 

/* 初始化加密参数 
 *  选定多项式模数
 *  选定系数模数
 *  选定噪声模数
 */

	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;
  time_start = chrono::high_resolution_clock::now();

	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree =1024;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	
	parms.set_plain_modulus(2);
	auto context = SEALContext::Create(parms);
	print_parameters(context);
	cout << endl;

/** 初始化 
 *  生成公私钥对
 */
	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();	
	
	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);
	
	IntegerEncoder encoder(context);
  
/** 根据加密参数初始化编码器 
 *  将数字编码成多项式
 */

	srand((int)time(0));
	int valuea = 5033333;
	Plaintext plain1 = encoder.encode(valuea);
	cout << "encode " << valuea << " as polynomial " << plain1.to_string()
	    << " (plain1)," << endl;

	int valueb = 713333;
	Plaintext plain2 = encoder.encode(valueb);
	cout << "encode " << valueb << " as polynomial " << plain2.to_string()
	    << " (plain2)." << endl;
 
	int randx = random(100);
	Plaintext plain3 = encoder.encode(randx);
	cout << "encode " << randx << " as polynomial " << plain3.to_string()
	    << " (plain3)." << endl;
	
	int randy = random(100);
	Plaintext plain4 = encoder.encode(randy);
	cout << "encode " << randy << " as polynomial " << plain4.to_string()
	    << " (plain4)." << endl;

/** 根据加密参数初始化加密器 
 *  将多项式加密
 */
	
	Ciphertext encrypted1, encrypted2, encrypted3, encrypted4;
	encryptor.encrypt(plain1, encrypted1);
	encryptor.encrypt(plain2, encrypted2);
	encryptor.encrypt(plain3, encrypted3);
	encryptor.encrypt(plain4, encrypted4);
	cout << "    + Noise budget in encrypted1: "
	    << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;
	cout << "    + Noise budget in encrypted2: "
	    << decryptor.invariant_noise_budget(encrypted2) << " bits" << endl;
	cout << "    + Noise budget in encrypted3: "
	    << decryptor.invariant_noise_budget(encrypted3) << " bits" << endl;
	cout << "    + Noise budget in encrypted4: "
	    << decryptor.invariant_noise_budget(encrypted4) << " bits" << endl;


/** 根据加密参数初始化运算器 
 *  在密文多项式上进行运算
 */
	
	Ciphertext encrypted_result1;
	cout << "Compute encrypted_result = encrypted1 * encrypted3 + encrypted4." << endl;
	evaluator.multiply(encrypted1, encrypted3, encrypted_result1);//这是一个负门操作，存入encrypted_result
	evaluator.add_inplace(encrypted_result1, encrypted4); //内置加门操作，存入encrypted_result
	cout << "    + Noise budget in encrypted_result: "
	    << decryptor.invariant_noise_budget(encrypted_result1) << " bits" << endl;
	Plaintext plain_result1;
	cout << "Decrypt encrypted_result1 to plain_result1." << endl;
	decryptor.decrypt(encrypted_result1, plain_result1);  //解密，存入plain_result

	Ciphertext encrypted_result2;
	cout << "Compute encrypted_result = encrypted2 * encrypted3 + encrypted4." << endl;
	evaluator.multiply(encrypted2, encrypted3, encrypted_result2);//这是一个负门操作，存入encrypted_result
	evaluator.add_inplace(encrypted_result2, encrypted4); //内置加门操作，存入encrypted_result
	cout << "    + Noise budget in encrypted_result: "
	    << decryptor.invariant_noise_budget(encrypted_result2) << " bits" << endl;
	Plaintext plain_result2;
	cout << "Decrypt encrypted_result2 to plain_result2." << endl;
	decryptor.decrypt(encrypted_result2, plain_result2);  //解密，存入plain_result

/** 调用之前生成的编码器解码 
 *  将明文多项式结果解码成数字
 */
	cout << "    + Plaintext polynomial: " << plain_result1.to_string() << endl;

	cout << "Decode plain_result1." << endl;	    
	cout << "    + Decoded integer: " << encoder.decode_int32(plain_result1);	   
	cout << "...... Correct." << endl;
	
	cout << "    + Plaintext polynomial: " << plain_result2.to_string() << endl;
	    
	cout << "Decode plain_result2." << endl;	    
	cout << "    + Decoded integer: " << encoder.decode_int32(plain_result2);	   
	cout << "...... Correct." << endl;

  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "Done [" << time_diff.count() << " microseconds]" << endl;

	return 0;
}
