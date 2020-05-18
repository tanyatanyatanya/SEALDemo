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

/** 初始化加密参数 
 *  选定多项式模数
 *  选定系数模数
 *  选定噪声模数
 */

	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;

	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree =2048;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	
	parms.set_plain_modulus(2);
	auto context = SEALContext::Create(parms);
	print_parameters(context);
	cout << endl;

/** 各种生成器初始化 
 *  生成公私钥对
 */
  time_start = chrono::high_resolution_clock::now();
	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();	
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "Key generation time:" << time_diff.count() << " microseconds" << endl;
	
	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);
	
	IntegerEncoder encoder(context);
  
/** 根据加密参数初始化编码器 
 *  将数字编码成多项式
 */

	srand((int)time(0));
	int data = random(100);

	cout << "-----data: " << data << "-----"<< endl;

  time_start = chrono::high_resolution_clock::now();
	Plaintext plain1 = encoder.encode(data);
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "encoding time:" << time_diff.count() << " microseconds" << endl;

/** 根据加密参数初始化加密器 
 *  将多项式加密
 */
	
	Ciphertext encrypted1;
 
  time_start = chrono::high_resolution_clock::now();
	encryptor.encrypt(plain1, encrypted1);
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "encryption time:" << time_diff.count() << " microseconds" << endl;


/** 根据加密参数初始化运算器 
 *  在密文多项式上进行运算
 *  取负 - nagate
 *  求和 - add
 *  求差 - sub
 *  求积 - mutiply
 */
	
	Ciphertext encrypted_result1;

	time_start = chrono::high_resolution_clock::now();
	evaluator.negate(encrypted1, encrypted_result1);
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "negate time:" << time_diff.count() << " microseconds" << endl;

	time_start = chrono::high_resolution_clock::now();
	evaluator.square(encrypted1, encrypted_result1);
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "square time:" << time_diff.count() << " microseconds" << endl;

  time_start = chrono::high_resolution_clock::now();
	evaluator.multiply(encrypted1, encrypted1,encrypted_result1); 
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "multplication time:" << time_diff.count() << " microseconds" << endl;

	time_start = chrono::high_resolution_clock::now();
	evaluator.add(encrypted1, encrypted1,encrypted_result1);
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "addition time:" << time_diff.count() << " microseconds" << endl;
      
	time_start = chrono::high_resolution_clock::now();
	evaluator.sub_inplace(encrypted_result1, encrypted1);
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "substract time:" << time_diff.count() << " microseconds" << endl;

 	Plaintext plain_result1;
  
	time_start = chrono::high_resolution_clock::now();
	decryptor.decrypt(encrypted_result1, plain_result1);  //解密，存入plain_result
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "decryption time:" << time_diff.count() << " microseconds" << endl;


/** 调用之前生成的编码器解码 
 *  将明文多项式结果解码成数字
 */
 
  time_start = chrono::high_resolution_clock::now();
	int result = encoder.decode_int32(plain_result1);	   
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "decoding time:" << time_diff.count() << " microseconds" << endl;

	cout << "-----result: " << result << "-----"<< endl;

	return 0;
}
