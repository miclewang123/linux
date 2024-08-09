#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/kthread.h>
#include <linux/version.h>
#include "swcsm36.h"

unsigned char inbuf1[8194],outbuf1[8192],tmpbuf1[8192];
struct task_struct *t1 = NULL;
struct task_struct * pthread = NULL;
unsigned long long g_unTotalLength=0; //
unsigned int g_unTotalTimes=0; //
int repeat = 1;

static int MyPrintk(void *data)  //线程用来显示性能 30S后自动退出
{  
	unsigned int speed, starttimes;   
    unsigned long long startlength;
	unsigned int i = 0;

 	printk("MyPrintk thread ok\n");

	while(repeat)  
	{  
	//	if(repeat){
		//if(i<10){
			starttimes = g_unTotalTimes;
			startlength = g_unTotalLength;
			//mdelay(1000);
			msleep(1000);
			//SLEEP_MILLI_SEC(1000);  
			speed =  (g_unTotalLength-startlength)*8/1024/1024;
 	  		printk("SPEED  = %d Mbps  ", speed);
 	 		printk("TPS = 0x%x Tps  ",g_unTotalTimes-starttimes);
 	 	  	printk("i=%d s\n",i);
 //	  	}
 //	  	else{
	// 	  	//repeat = 0;	 
//	 	  	break;
 //	  	}
		i++;
	}  
	return 0;  
}
int PrintData(char *itemName, char *sourceData, int dataLength, int rowCount)
{
	int i, j;
	
	if((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
		return -1;
	
	if(itemName != NULL)
		printk("%s[%d]:\n", itemName, dataLength);
	
	for(i=0; i<(int)(dataLength/rowCount); i++)
	{
		printk("%08x  ",i * rowCount);

		for(j=0; j<(int)rowCount; j++)
		{
			printk("%02x ", *(unsigned char*)(sourceData + i*rowCount + j));
		}

		printk("\n");
	}

	if (!(dataLength % rowCount))
		return 0;
	
	printk("%08x  ", (dataLength/rowCount) * rowCount);

	for(j=0; j<(int)(dataLength%rowCount); j++)
		printk("%02x ",*(unsigned char*)(sourceData + (dataLength/rowCount)*rowCount + j));
	printk("\n");
	
	return 0;
}

int t_SM1CBCDecEnc(int num)
{
	unsigned int  tmpLen, outLen;
  	int ReturnValue, len = 8000;
  
	unsigned char pbKeyValue[32] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
	unsigned char pbIV[16] = {0xe8,0x3d,0x17,0x15,0xac,0xf3,0x48,0x63,0xac,0xeb,0x93,0xe0,0xe5,0xab,0x8b,0x90};
	unsigned char pbPlainText[32] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	unsigned char pbCipherText[32] = {0x3a,0x70,0xb5,0xd4,0x9a,0x78,0x2c,0x07,0x2d,0xe1,0x13,0x43,0x81,0x9e,0xc6,0x59,0xf8,0xfc,0x7a,0xf0,0x5e,0x7c,0x6d,0xfb,0x5f,0x81,0x09,0x0f,0x0d,0x87,0x91,0xb2};
	   
	len = 1024;
	memcpy(inbuf1,pbPlainText,32);
	
	ReturnValue = Kel_SM1CBCEnc(0, pbKeyValue,16, pbIV, inbuf1, len, outbuf1, &outLen);
	if(ReturnValue)
	{
		printk("Test Kel_SM1CBCEnc ERRORNUM[0x%x]!\n", ReturnValue);
	   	return 1;
	}
	
	if (memcmp(outbuf1, pbCipherText, 32))
	{
		printk("cmp Kel_SM1CBCEnc data error\n");
	//	return 1;
	}	
   	//PrintData("outbuf1", outbuf1, 32, 16);
	g_unTotalLength += len;
	g_unTotalTimes++;
	
	memcpy(outbuf1,pbCipherText,32);
	ReturnValue = Kel_SM1CBCDec(0, pbKeyValue,16, pbIV, outbuf1, len, tmpbuf1, &tmpLen);
	if(ReturnValue)
	{
		printk("Test Kel_SM1CBCDec ERRORNUM[0x%x]!\n",ReturnValue);
	    return 1;
	}
	if(memcmp(inbuf1, tmpbuf1, len))
	{
	    printk("Cmp Kel_SM1CBCDec Error! %d, %d\n", num, tmpLen);
	    //return 1;
	}
	g_unTotalLength += len;
	g_unTotalTimes++;
	//PrintData("tmpbuf1", tmpbuf1, 32, 16);
	//printk(KERN_ERR"test t_SM1CBCDecEnc OK! %d\n", tmpLen);
	
	return 0;
}


int t_SM1ECBDecEnc1(unsigned int num)
{
	unsigned int  tmpLen,outLen;
	unsigned int ReturnValue, len = 0; 
	unsigned char pbKeyValue[32] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
	unsigned char pbPlainText[16] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
	unsigned char pbCipherText[16] = {0x6d,0x7f,0x45,0xb0,0x8b,0xc4,0xd9,0x66,0x44,0x4c,0x86,0xc2,0xb0,0x7d,0x29,0x93};

	len = 1024;
  	memcpy(inbuf1,pbPlainText,16);
  
	ReturnValue = Kel_SM1ECBEnc(0, pbKeyValue,16, inbuf1, len, outbuf1, &outLen);
	if(ReturnValue)
	{
	    printk("Test Kel_SM1ECBEnc ERROR!ReturnValue = 0x%4x\n",ReturnValue);
	    return 1;
	}
	if (memcmp(outbuf1, pbCipherText, 16))
	{
		printk(KERN_ERR"SM1 cmp Kel_SM1ECBEnc error\n");
		//return 1;
	} 
	//PrintData("SM1ECBEnc cipherdata", outbuf1, 32, 16);
	g_unTotalLength += len;
	g_unTotalTimes++;
	 	
	ReturnValue = Kel_SM1ECBDec(0, pbKeyValue,16, outbuf1, outLen, tmpbuf1, &tmpLen);
	if(ReturnValue)
	{
		printk("Test Kel_SM1ECBDec ERROR!ReturnValue = 0x%4x\n",ReturnValue);
	    return 1;
	}
	if (memcmp(tmpbuf1, inbuf1, tmpLen))
	{
		printk(KERN_ERR" sm1 %d cmp Kel_SM1ECBDec error %d\n", num, tmpLen);	
		//return 1;
	}
  	//printk("test t_SM1ECBDecEnc1 OK! %d\n", tmpLen);
	//PrintData("SM1ECBEnc cipherdata", tmpbuf1, 32, 16);
	g_unTotalLength += len;
	g_unTotalTimes++;
	return 0;
}

int t_SM4CBCDecEnc(int num)
{
	unsigned int  tmpLen, outLen;
  	int ReturnValue, len ;
  
	unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char pbIV[16] = {0xeb,0xee,0xc5,0x68,0x58,0xe6,0x04,0xd8,0x32,0x7b,0x9b,0x3c,0x10,0xc9,0x0c,0xa7};
	unsigned char pbPlainText[32] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x29,0xbe,0xe1,0xd6,0x52,0x49,0xf1,0xe9,0xb3,0xdb,0x87,0x3e,0x24,0x0d,0x06,0x47};
	unsigned char pbCipherText[32] = {0x3f,0x1e,0x73,0xc3,0xdf,0xd5,0xa1,0x32,0x88,0x2f,0xe6,0x9d,0x99,0x6c,0xde,0x93,0x54,0x99,0x09,0x5d,0xde,0x68,0x99,0x5b,0x4d,0x70,0xf2,0x30,0x9f,0x2e,0xf1,0xb7};
	
	len = 1024;

	memcpy(inbuf1,pbPlainText,32);
	ReturnValue = Kel_SM4CBCEnc(0, pbKeyValue,16, pbIV, inbuf1, len, outbuf1, &outLen);
	if(ReturnValue)
	{
		printk("Test Kel_SM4CBCEnc ERRORNUM[0x%x]!\n",ReturnValue);
	   	return 1;
	}	
	if (memcmp(outbuf1, pbCipherText, 32))
	{
		printk(" sm4 cmp Kel_SM4CBCEnc error\n");
		return 1;
	}	
	g_unTotalLength += len;
	g_unTotalTimes++;
		
	ReturnValue = Kel_SM4CBCDec(0, pbKeyValue,16, pbIV, outbuf1, len, tmpbuf1, &tmpLen);
	if(ReturnValue)
	{
		printk("Test Kel_SM4CBCDec ERRORNUM[0x%x!\n",ReturnValue);
	    return 1;
	}
	if(memcmp(inbuf1, tmpbuf1, len))
	{
	    printk("SM4 Cmp Kel_SM4CBCDec Error! %d, %d\n", num, tmpLen);
	    return 1;
	}
	g_unTotalLength += len;
	g_unTotalTimes++;
	
	//printk(KERN_ERR"t_SM4CBCDecEnc:  Cmp OK! %d\n", tmpLen);

	return 0;
}


int t_SM4ECBDecEnc1(unsigned int num)
{
	unsigned int  tmpLen,outLen;
	unsigned int ReturnValue, len = 0; 
	unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char pbPlainText[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char pbCipherText[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
		
	len = 1024;

	memcpy(inbuf1,pbPlainText,16);
	
	ReturnValue = Kel_SM4ECBEnc(0, pbKeyValue,16, inbuf1, len, outbuf1, &outLen);
	if(ReturnValue)
	{
	    printk("Test Kel_SM4ECBEnc ERROR!ReturnValue = 0x%4x\n",ReturnValue);
	    return 1;
	}
	if (memcmp(outbuf1, pbCipherText, 16))
	{
		printk(KERN_ERR"cmp Kel_SM4ECBEnc error\n");
		return 1;
	} 
	//printk(KERN_ERR"Kel_SM4ECBEnc  Enc ok\n");
	g_unTotalLength += len;
	g_unTotalTimes++;
	
	ReturnValue = Kel_SM4ECBDec(0, pbKeyValue,16, outbuf1, outLen, tmpbuf1, &tmpLen);
	if(ReturnValue)
	{
	    printk("Test Kel_SM4ECBDec ERROR!ReturnValue = 0x%4x\n",ReturnValue);
	    return 1;
	}
	if (memcmp(tmpbuf1, inbuf1, tmpLen))
	{
		printk(KERN_ERR"SM4 %d cmp Kel_SM4ECBDec error %d\n", num, tmpLen);
		return 1;
	}
	g_unTotalLength += len;
	g_unTotalTimes++;
	//printk(KERN_ERR"test t_SM4ECBDecEnc1 OK! %d\n", tmpLen);

	return 0;
}

int t_SynSM31(int num)
{
	SM3_CONTEXT SM3Context;	 
	ECCrefPublicKey pubkey;
	
	unsigned char bHashData[64] = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};
	unsigned char bHashStdResult64[32] = {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
										  0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};
										  	
	unsigned char x[32] = {0xec,0x37,0xa5,0xa6,0xdb,0x31,0x01,0xec,0xfc,0x39,0x08,0xc9,0xce,0x1f,0xfe,0x7b,
						   0x69,0xe6,0x8a,0x8c,0x3d,0x07,0x31,0x25,0xc4,0x18,0xa3,0x8a,0xd3,0x21,0x91,0x44};
												
	unsigned char y[32] = {0x8d,0xa4,0x75,0x85,0xb4,0x3b,0xba,0xda,0x6b,0x4b,0xbe,0xe8,0x94,0xa2,0x38,0xe6,
						   0x00,0xf0,0x29,0xb6,0xe9,0x1c,0x1f,0x33,0x1c,0x38,0x55,0x81,0x04,0xb9,0xcb,0x6e};
							           
	unsigned char bHashStdResult[32] = {0x64,0x9d,0x02,0x0a,0x21,0x2d,0x0e,0x66,0xba,0x3b,0xeb,0xa8,0x85,0xc9,0x4d,0xe6,
										0x54,0x5b,0x15,0x57,0x72,0x8d,0x10,0x96,0xfe,0x7b,0x6c,0xb0,0xb8,0x1f,0x33,0xbd};
	unsigned char bHashStdResultpub[32] = {0x7e,0xa6,0x54,0x4c,0x2b,0x4b,0x6a,0xc7,0xdf,0x9c,0x3f,0x95,0x4b,0xf9,0x3c,0x15,
										   0x8f,0x49,0x44,0x89,0x91,0xbe,0xd5,0xa0,0x6e,0x97,0x48,0xce,0x93,0x73,0x7c,0x54};

	unsigned char bHashResult[32];
	unsigned int rv;
	unsigned int i,plainlen;
	
	pubkey.bits = 256;
	memcpy(pubkey.x,x,32);
	memcpy(pubkey.y,y,32);
		
	plainlen = 8193;
	for(i=0;i<plainlen;i++)
		inbuf1[i] = (i+1)%255;

	rv = Kel_SM3_Init(&SM3Context, &pubkey, "1234567812345678", 16);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Init ERROR[0x%08x]\n", rv);
		return rv;
	}
  
	rv = Kel_SM3_Update(&SM3Context, inbuf1, plainlen);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Update ERROR[0x%08x]\n", rv);
		return rv;
	}

	memset(bHashResult, 0x0, 32);
	rv = Kel_SM3_Final(&SM3Context, bHashResult);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Final ERROR![0x%08x]\n", rv);
		return rv;
	}

	if(memcmp(bHashStdResultpub, bHashResult, 32))
	{
		printk(KERN_ERR"bHashStdResultpub CMP ERROR!\n");
		return -1;
	}
//	printk(KERN_ERR"plainlen = %d CMP bHashStdResultpub SUCCESS!\n",plainlen);	
	g_unTotalLength += plainlen;
	g_unTotalTimes += 3;
	
	
	/******************************************************/	
	rv = Kel_SM3_Init(&SM3Context, 0, 0, 0);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Init ERROR[0x%08x]\n", rv);
		return rv;
	}

	rv = Kel_SM3_Update(&SM3Context, bHashData, 64);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Update ERROR[0x%08x]\n", rv);
		return rv;
	}

	memset(bHashResult, 0x0, 32);
	rv = Kel_SM3_Final(&SM3Context, bHashResult);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Final ERROR![0x%08x]\n", rv);
		return rv;
	}
	
	if(memcmp(bHashStdResult64, bHashResult, 32))
	{
		printk(KERN_ERR"CMP bHashStdResult64 ERROR!\n");
  		PrintData("output hash value", bHashResult, 32, 16);
		return -1;
	}
//	printk(KERN_ERR"plainlen = %d CMP 64 SUCCESS!\n",plainlen);
	
	g_unTotalLength += 64;
	g_unTotalTimes += 3;
	
	/******************************************************/
	rv = Kel_SM3_Init(&SM3Context, 0, 0, 0);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Init ERROR[0x%08x]\n", rv);
		return rv;
	}

	rv = Kel_SM3_Update(&SM3Context, inbuf1, plainlen);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Update ERROR[0x%08x]\n", rv);
		return rv;
	}

	memset(bHashResult, 0x0, 32);
	rv = Kel_SM3_Final(&SM3Context, bHashResult);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Final ERROR![0x%08x]\n", rv);
		return rv;
	}
	
	if(memcmp(bHashStdResult, bHashResult, 32))
	{
		printk(KERN_ERR"bHashStdResult CMP ERROR!\n");
		PrintData("output hash value", bHashResult, 32, 16);

		return -1;
	}
//	printk(KERN_ERR"plainlen = %d CMP 8193 SUCCESS!\n",plainlen);
	g_unTotalLength += plainlen;
	g_unTotalTimes += 3;
	
	return 0;	
}

int inittest(void *argv)  
{
  	int i, rv;
	// struct timeval start;
	// struct timval end;
#	if 	LINUX_VERSION_CODE > KERNEL_VERSION(4,20,17)  
		struct timespec64 now;
#	endif
	
	repeat = 1;
	printk("inittest thread ok\n");
	while(repeat< 3){
#	if 	LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)     
	 // 	do_gettimeofday(&start);
#	else
	  	ktime_get_real_ts64(&now);
		// start.tv_sec = now.tv_sec;
		// start.tv_usec = now.tv_nsec/1000;
#	endif
		for(i=0; i<1000; i++)
	  	{	
	  	#if 1
	  		rv = t_SM1CBCDecEnc(i);
			if(rv)
			{
				printk(KERN_ERR"t_SM1CBCDecEnc error 0x%x!\n",rv);
				break;
			}	

	 	  	rv =  t_SM4CBCDecEnc(i);
	 	  	if(rv)
		   	{
				printk(KERN_ERR"t_SM4CBCDecEnc error 0x%x !\n",rv);
				break;
		   	}  

			rv =  t_SM4ECBDecEnc1(i);
		   	if(rv)
		   	{
		      	printk(KERN_ERR"t_SM4ECBDecEnc1 error 0x%x!\n",rv);
			    break;
		   	}  
  
		   	rv = t_SM1ECBDecEnc1(i);
		   	if(rv)
		   	{
		      	printk(KERN_ERR"t_SM1ECBDecEnc1 error 0x%x!\n",rv);
			    break;
	     	}
		#endif
	     	rv = t_SynSM31(i);	
	     	if(rv)
		   	{
		      	printk(KERN_ERR"t_SynSM31 error 0x%x!\n",rv);
			    break;
	     	}

		}
#	if 	LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)   
//		do_gettimeofday(&end);	
#	else
		ktime_get_real_ts64(&now);
		// end.tv_sec = now.tv_sec;
		// end.tv_usec = now.tv_nsec/1000;
#endif
		//printk(KERN_ERR"time %d s\n", (int)(end.tv_sec-start.tv_sec));
		msleep(400);
		//repeat = 0;
		repeat ++;
 	}   
	repeat = 0;
	msleep(1000);
	 return 0;
}

int mod_init_func1(void)
{     
	 printk(KERN_ERR "Begin......\n");
#if 0
	unsigned int rv, i;
 	for(i=0; i<1; i++)
  	{	/*
 		rv =  t_SM4CBCDecEnc(i);
	   	if(rv)
	   	{
			printk(KERN_ERR"t_SM4CBCDecEnc error!\n");
			return -1;
	   	}  
		rv =  t_SM4ECBDecEnc1(i);
	   	if(rv)
	   	{
	    	printk(KERN_ERR"t_SM4ECBDecEnc1 error!\n");
		    return -1;
	   	}  
 		
			  
	   	rv = t_SM1ECBDecEnc1(i);
	   	if(rv)
	   	{
	   		printk(KERN_ERR"t_SM1ECBDecEnc1 error!\n");
		    return -1;
     	}
     	t_SynSM31(i);
			*/  
		rv = t_SM1CBCDecEnc(i);
		if(rv)
		{
			printk(KERN_ERR"t_SM1CBCDecEnc error!\n");
			return -1;
		}
		rv = t_SM1ECBDecEnc1(i);
	   	if(rv)
	   	{
	   		printk(KERN_ERR"t_SM1ECBDecEnc1 error!\n");
		    return -1;
     	}
	}
#else

	t1 =  kthread_create(inittest, NULL, "inittest");
	pthread = kthread_create(MyPrintk, NULL, "printk");
	
	if (!IS_ERR(t1))
		wake_up_process(t1);
	if (!IS_ERR(pthread))
		wake_up_process(pthread);
#endif

	printk("test end....\n");

	return 0;
}

void mod_exit_func1(void)
{

	printk(KERN_ERR "test module exit........\n");
}

MODULE_LICENSE("GPL");
module_init(mod_init_func1);
module_exit(mod_exit_func1);

