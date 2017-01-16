
#import <Foundation/Foundation.h>

typedef enum {
    NSStringProcXEncoded,
    NSStringProcXDecoded
} NSStringProcX;


@interface NSString (Base64)

- (NSString *)procXXString:(NSString *)auth_key operation:(NSStringProcX)operation encoding:(NSStringEncoding)encoding;

- (NSString *)procXEncoded:(NSString *)key encoding:(NSStringEncoding)encoding;

- (NSString *)procXEncoded:(NSString *)key;

- (NSString *)procXDecoded:(NSString *)key encoding:(NSStringEncoding)encoding;

- (NSString *)procXDecoded:(NSString *)key;

@end
