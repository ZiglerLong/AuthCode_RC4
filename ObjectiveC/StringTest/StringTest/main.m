//
//  main.m
//  StringTest
//
//  Created by Apple on 16/6/12.
//  Copyright © 2016年 Ziegler Long. All rights reserved.
//

#import "StringProcX.h"
#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
        
        //密钥：服务端与APP端应该统一密钥...
        NSString *key = @"#*Merg^QaNy";
        //待加密的明文
        NSString *message = @"hello world，我操";
        NSLog(@"Origin:%@",message);
        //加密后的密文
        NSString *a = [message procXEncoded:key];
        NSLog(@"Encode:%@", a);
        //解密后的明文
        NSString *b = [a procXDecoded:key];
        NSLog(@"Decode:%@", b);
    }
    return 0;
}
