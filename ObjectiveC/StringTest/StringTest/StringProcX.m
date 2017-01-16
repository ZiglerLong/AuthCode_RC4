#import "StringProcX.h"
#import <CommonCrypto/CommonDigest.h>

#import <Availability.h>
#if !__has_feature(objc_arc)
#error This library requires automatic reference counting
#endif

@implementation NSString (Base64)

- (NSString *)md5 {
    const char *concat_str = [self UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(concat_str, strlen(concat_str), result);
    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < 16; i++)
        [hash appendFormat:@"%02x", result[i]];
    return [hash lowercaseString];
}

- (NSString *)procXXString:(NSString *)auth_key operation:(NSStringProcX)operation encoding:(NSStringEncoding)encoding
{
    NSMutableArray *rndkey = [NSMutableArray array];
    NSMutableArray *box = [NSMutableArray array];
    NSMutableArray *result = [NSMutableArray array];
    
    NSUInteger ckey_length = 4;
    NSString *key =  [[auth_key md5] md5]; //两轮MD5
    NSString *keya = [[key substringToIndex:16] md5];
    NSString *keyb = [[key substringWithRange:NSMakeRange(16, 16)] md5];
    //替换掉可能会引起URL错误的符号
    NSString *repl = [[[self stringByReplacingOccurrencesOfString:@"[a]" withString:@"+"] stringByReplacingOccurrencesOfString:@"[d]" withString:@"/"] stringByReplacingOccurrencesOfString:@"[s]" withString:@"="];
    //keyc 加入时间因子，保证每次加密后，结果都不一样
    NSTimeInterval atn = [[NSDate date] timeIntervalSince1970];
    double ix = atn;
    NSString *kk = [[NSString stringWithFormat:@"%f",ix] md5];
    NSString *keyc = (operation==NSStringProcXDecoded) ? [repl substringToIndex:ckey_length] : [kk substringWithRange:NSMakeRange(kk.length-ckey_length, ckey_length)];
    //NSString *keyc = (operation==NSStringProcXDecoded) ? [repl substringToIndex:ckey_length] : @"long";
    
    NSString *cryptkey = [NSString stringWithFormat:@"%@%@",keya,[[NSString stringWithFormat:@"%@%@",keya,keyc] md5]];
    NSUInteger key_length = cryptkey.length;
    
    Byte *bytes = nil;
    NSUInteger byte_length = 0;
    
    if(operation==NSStringProcXDecoded){
        NSString *toDecode = [repl substringFromIndex:ckey_length];
        NSData *decodeData = [[NSData alloc] initWithBase64EncodedString:toDecode options:0];
        bytes = (Byte*)[decodeData bytes];
        byte_length = decodeData.length;
    }else{
        NSString *str = [NSString stringWithFormat:@"0000000000%@%@",[[[NSString stringWithFormat:@"%@%@",repl,keyb] md5] substringToIndex:16],repl];
        NSData *data_utf8 = [str dataUsingEncoding:NSUTF8StringEncoding];
        bytes = (Byte*)[data_utf8 bytes];
        byte_length = [data_utf8 length];
    }
    //生成密钥数组
    for(int i = 0; i <= 255; i++) {
        [box addObject:[NSNumber numberWithUnsignedShort:i]];
        [rndkey addObject:[NSNumber numberWithUnsignedShort:[cryptkey characterAtIndex:i%key_length]]];
    }
    //打乱密钥数组，瞬间高大上了有木有
    int j = 0;
    for(int i = 0; i < 256; i++) {
        unsigned short b = [[box objectAtIndex:i] unsignedShortValue];
        unsigned short r = [[rndkey objectAtIndex:i] unsignedShortValue];
        j = (j + b + r) % 256;
        unsigned short bi = [[box objectAtIndex:i] unsignedShortValue];
        [box replaceObjectAtIndex:i withObject:[box objectAtIndex:j]];
        [box replaceObjectAtIndex:j withObject:[NSNumber numberWithUnsignedShort:bi]];
    }
    int a = 0;
    j = 0;
    for(int i = 0; i < byte_length; i++) {
        a = (a + 1) % 256;
        unsigned short b = [[box objectAtIndex:a] unsignedShortValue];
        j = (j + b) % 256;
        unsigned short bi = [[box objectAtIndex:a] unsignedShortValue];
        [box replaceObjectAtIndex:a withObject:[box objectAtIndex:j]];
        [box replaceObjectAtIndex:j withObject:[NSNumber numberWithUnsignedShort:bi]];
        unsigned short sc = 0;
        sc = bytes[i];
        unsigned short bx = [[box objectAtIndex:(([[box objectAtIndex:a] unsignedShortValue] + [[box objectAtIndex:j] unsignedShortValue]) % 256)] unsignedShortValue];
        unsigned short k = sc ^ bx;
        [result addObject: [NSNumber numberWithUnsignedShort:k]];
    }
    //
    if(operation==NSStringProcXDecoded){
        //被迫使用C的无敌指针大法...
        //用 Byte 指针代替 char 指针，因为 char 在某些情况下会被非法截断...
        Byte *pDec = (Byte*)malloc(result.count);
        for (int i=0; i<result.count; i++) {
            pDec[i] = [[result objectAtIndex:i] shortValue];
        }
        //用了 Byte* ，所以这里换种方法初始化 NSString
        NSString *from = [[NSString alloc] initWithBytes:pDec length:result.count encoding:NSUTF8StringEncoding];
        free(pDec);
        //密文头部的26个字节用来判断时间与内容HASH值，因此密文不可能只有26个字节
        if(from.length<27){
            return @"";
        }
        NSString *s1 = [from substringToIndex:10];
        NSUInteger iTS = [s1 integerValue];
        NSDate *date = [NSDate date];
        NSTimeInterval aInterval = [date timeIntervalSince1970];
        NSUInteger iTN = aInterval;
        NSString *s2 = [from substringWithRange:NSMakeRange(10, 16)];
        //验证有效时间与明文的HASH是否正确
        NSString *uns = [from substringFromIndex:26];
        NSString *e2 = [[[NSString stringWithFormat:@"%@%@",uns,keyb] md5] substringToIndex:16];
        if ((iTS==0 || iTS-iTN>0) && [s2 isEqualToString:e2]) {
            return uns;
        }else{
            return @"";
        }
    } else {
        //加密
        //同上，因为用 Byte 指针代替 char 指针
        Byte *pEnc = (Byte*)malloc(result.count);
        for (int i=0; i<result.count; i++) {
            pEnc[i] = [[result objectAtIndex:i] shortValue];
        }
        NSData *toEncode = [NSData dataWithBytes:pEnc length:result.count];
        NSString *ret = [toEncode base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
        //夹带一个时间因子，没什么卵用。可以混淆视听...
        NSString *retX = [NSString stringWithFormat:@"%@%@",keyc, ret];
        free(pEnc);
        //把可能会导致URL错误的符号替换掉...
        //替换逻辑： + 变 [a] ，/ 变 [d] ，= 变 [s] ，解密时正好相反
        retX = [[[retX stringByReplacingOccurrencesOfString:@"+" withString:@"[a]"] stringByReplacingOccurrencesOfString:@"/" withString:@"[d]"] stringByReplacingOccurrencesOfString:@"=" withString:@"[s]"];

        return retX;
    }
}

- (NSString *)procXEncoded:(NSString *)key encoding:(NSStringEncoding)encoding
{
    return [self procXXString:key operation:NSStringProcXEncoded encoding:encoding];
}

- (NSString *)procXEncoded:(NSString *)key
{
    return [self procXEncoded:key encoding:NSUTF8StringEncoding];
}

- (NSString *)procXDecoded:(NSString *)key encoding:(NSStringEncoding)encoding
{
    return [self procXXString:key operation:NSStringProcXDecoded encoding:encoding];
}

- (NSString *)procXDecoded:(NSString *)key
{
    return [self procXDecoded:key encoding:NSUTF8StringEncoding];
}

@end
