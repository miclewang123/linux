#ifndef _SWCSM36_H_
#define _SWCSM36_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  unsigned long *inbufptr;
  unsigned long inbuflen;
  unsigned long *outbufptr;
  unsigned long outbuflen;
}
SWXA_OperationBuffer;

typedef struct SM3_CONTEXT_st
{
    unsigned int stateIV[8];	/*state (ABCDEFGH)*/
    unsigned int count[2];	/*number of bits, modulo 2^64 (lsb first) */
    unsigned char  buffer[64];	/* input buffer */
} SM3_CONTEXT;

typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[32]; 
	unsigned char y[32]; 
} ECCrefPublicKey;


//密码卡一次处理的明文长度最大为8000字节，超过8000上层需要分包。
extern int Kel_SM4CBCDec(unsigned int keynum, unsigned char *key, unsigned int keylen,unsigned char *iv, 
									unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);
	
extern int Kel_SM4CBCEnc(unsigned int keynum, unsigned char *key, unsigned int keylen,unsigned char *iv, 
									unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);
extern int Kel_SM4ECBDec(unsigned int keynum, unsigned char *key,unsigned int keylen, 
										unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);
extern int Kel_SM4ECBEnc(unsigned int keynum, unsigned char *key,unsigned int keylen, 
									unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);	
									
extern int Kel_SM1ECBEnc(unsigned int keynum, unsigned char *key,unsigned int keylen, 
	unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);

extern int Kel_SM1ECBDec(unsigned int keynum, unsigned char *key,unsigned int keylen, 
	unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);

extern int Kel_SM1CBCEnc(unsigned int keynum, unsigned char *key, unsigned int keylen,unsigned char *iv, 
	unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);

extern int Kel_SM1CBCDec(unsigned int keynum, unsigned char *key, unsigned int keylen,unsigned char *iv, 
	unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);
	
extern int Kel_SM3_Init(SM3_CONTEXT *pCtx, ECCrefPublicKey *pucPublicKey, unsigned char  *pucID, unsigned int uiIDLength);
 
extern int Kel_SM3_Update(SM3_CONTEXT *pCtx, unsigned char *pbData, unsigned int uiDataLen);

extern int Kel_SM3_Final(SM3_CONTEXT *pCtx, unsigned char pbResult[32]);
//extern int Kel_CloseSession(void);
//extern int Kel_OpenSession(void);
#ifdef __cplusplus
}
#endif
   
#endif

/*

参数说明：[i]表示输入参数[o]表示输出参数
 keynum[i]：密钥索引  0表示使用外部密钥  1--32表示使用卡内对应索引的密钥
 key[i]：密钥索引为0时，外部密钥保存在key中；或表示外部密钥
 keylen[i]：密钥索引为0时，外部密钥的长度(8字节的整数倍且不大于32字节)；或表示外部密钥长度
 inbuf[i]：输入缓冲区
 inlen[i]：输入缓冲区数据长度
 outbuf[o]: 输出缓冲区
 outlen[o]： 输出长度
 iv[i]: cbc初始化矢量
 flag[i]：0表示如果当前索引存在密钥，直接返回；非0不关心当前位置密钥是否存在，强制存入密钥
 
 
 返回值：
 0：  操作成功
 -1： 输入参数有误
 -2： 当前密钥存在，不保存
 8：  表示使用的索引密钥不存在
 其他返回值： 操作过程失败
*/







