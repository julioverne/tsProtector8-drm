#import <CommonCrypto/CommonCrypto.h>

OBJC_EXTERN CFStringRef MGCopyAnswer(CFStringRef key) WEAK_IMPORT_ATTRIBUTE;

@implementation NSString (MD5)
+ (NSString*)md5:(NSString*)input
{
    const char* str = [input UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(str, strlen(str), result);
    NSMutableString *ret = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH*2];
    for(int i = 0; i<CC_MD5_DIGEST_LENGTH; i++) {
		[ret appendFormat:@"%02x",result[i]];
    }
    return ret;
}
+ (NSString*)encodeBase64WithData:(NSData*)theData
{
    const uint8_t* input = (const uint8_t*)[theData bytes];
    NSInteger length = [theData length];
    static char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    NSMutableData* data = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
    uint8_t* output = (uint8_t*)data.mutableBytes;
    NSInteger i;
    for (i=0; i < length; i += 3) {
        NSInteger value = 0;
        NSInteger j;
        for (j = i; j < (i + 3); j++) {
            value <<= 8;

            if (j < length) {
                value |= (0xFF & input[j]);
            }
        }
        NSInteger theIndex = (i / 3) * 4;
        output[theIndex + 0] =                    table[(value >> 18) & 0x3F];
        output[theIndex + 1] =                    table[(value >> 12) & 0x3F];
        output[theIndex + 2] = (i + 1) < length ? table[(value >> 6)  & 0x3F] : '=';
        output[theIndex + 3] = (i + 2) < length ? table[(value >> 0)  & 0x3F] : '=';
    }
    return [[[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding] autorelease];
}
@end

@implementation NSData (AES)
- (NSData *)AES128:(CCOperation)operation key:(const void *)key iv:(NSString *)iv
{		  //CCOperation: kCCDecrypt/kCCEncrypt
    /*char keyPtr[kCCKeySizeAES128];
    bzero(keyPtr, sizeof(keyPtr));
	if (key) {
		[key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
	}*/
    char ivPtr[kCCBlockSizeAES128 + 1];
    bzero(ivPtr, sizeof(ivPtr));
    if (iv) {
		[iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    }
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
					  kCCAlgorithmAES128,
					  kCCOptionPKCS7Padding,
					  key,
					  32,
					  ivPtr,
					  [self bytes],
					  dataLength,
					  buffer,
					  bufferSize,
					  &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
		return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}
@end

int main()
{
	NSFileManager *manager = [[[NSFileManager alloc] init] autorelease];
	
	NSString *pref_lice = @"//var/mobile/Library/Preferences/kr.typostudio.tsprotector.plist";
	NSString *version = @"1.1-2";
	
	static __strong NSString* UDID = [[NSString stringWithFormat:@"%@", (NSString*)MGCopyAnswer(CFSTR("UniqueDeviceID"))] copy];
	
	NSString *mountString1 = [NSString stringWithFormat:@"%@%@%@%@", @"c406b02554db5b8d22bf996fef6ffd43", UDID, version, @"f17045979bc9adfa5a448cc7388ce28e"];
	NSString *mountString2 = [NSString stringWithFormat:@"%@%@%@%@", @"59b96189e785bb8165e293159b80bb40", UDID, version, @"6870b01f0200cbad879e5d2f4389621f"];
	
	
	if (![manager fileExistsAtPath:pref_lice]) {
		NSDictionary *dict = [NSDictionary dictionary];
		[dict writeToFile:pref_lice atomically:YES];
	}
	
	NSMutableDictionary* pref_liceCheck = [[NSMutableDictionary alloc] initWithContentsOfFile:pref_lice];
	
	[pref_liceCheck setObject:UDID forKey:@"UDID"];
	[pref_liceCheck setObject:version forKey:@"version"];
	
	[pref_liceCheck setObject:[NSString md5:mountString1] forKey:@"\xEB\x82\x98\xEC\x97\x90\xEA\xB2\x8C\xEC\x93\xB0\xEB\x8A\x94\xED\x8E\xB8\xEC\xA7\x80"];
	[pref_liceCheck setObject:[NSString md5:mountString2] forKey:@"\xEC\x9D\xB8\xED\x98\x95\xEC\x9D\x98\xEA\xB8\xB0\xEC\x82\xAC"];
	
	const void * key1 = "\x80\x8C\x10\x6F\xB4\xB1\xDE\x86\x77\xA6\xD4\x79\x78\x73\xC7\x49\x95\xE7\x1E\xFB\xC3\x81\x6F\x02\xB6\xB1\x64\xDF\xA6\xBC\x37\xE2";
	const void * key2 = "\x54\x00\x8C\x8A\xCC\xC1\x18\xC5\x93\x03\x8E\x9E\x26\xDA\x42\xEF\x4B\x48\xD2\x16\xDF\x3F\xE2\x0C\xC3\xE0\xE8\x6D\x15\x09\x28\xC3";
	
	[pref_liceCheck setObject:[NSString encodeBase64WithData:[[UDID dataUsingEncoding:NSUTF8StringEncoding] AES128:kCCEncrypt key:key1 iv:nil]] forKey:@"\xEB\x82\xA0\xEC\x95\x84\xEB\x9D\xBC\x20\xEB\xB3\x91\xEC\x95\x84\xEB\xA6\xAC"];
	
	[pref_liceCheck setObject:[NSString encodeBase64WithData:[[@"999999999" dataUsingEncoding:NSUTF8StringEncoding] AES128:kCCEncrypt key:key1 iv:nil]] forKey:@"\xEB\xAF\xBC\xEB\xAC\xBC\xEC\x9E\xA5\xEC\x96\xB4\xEC\x9D\x98\x20\xEA\xBF\x88"];
	[pref_liceCheck setObject:[NSString encodeBase64WithData:[[@"999999999" dataUsingEncoding:NSUTF8StringEncoding] AES128:kCCEncrypt key:key2 iv:nil]] forKey:@"\xEC\x82\xAC\xEB\x9E\x8C\xEC\x82\xAC\xEB\x8A\x94\xEC\x84\xB8\xEC\x83\x81"];
	
	
	
	if (![pref_liceCheck writeToFile:pref_lice atomically:YES]) {
		printf("\n*** Error writing license to file! ***\n");
	} else {
		[manager setAttributes:@{@"mobile": NSFileOwnerAccountName,	@"mobile": NSFileGroupOwnerAccountName,	@0644: NSFilePosixPermissions,} ofItemAtPath:pref_lice error:nil];
		printf("\n*** License has been generated! ***\n");
	}
	
	printf("\n");
	printf("Respring!!!\n");
	printf("Respring!!!\n");
	printf("Respring!!!\n");
	printf("\n");
	printf("*** Keygen tsProtector 8 (iOS 8+) by julioverne ***\n");
	printf("\n");
	
	return 0;
}