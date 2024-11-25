/*
 * Copyright (c) 2011-2024, baomidou (jobob@qq.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.baomidou.mybatisplus.core.toolkit;

import com.baomidou.mybatisplus.core.exceptions.MybatisPlusException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES CBC模式加密工具类
 *
 * @author cryptocheck
 * @since 2024-11-25
 */
public class AES {


    /**
     * 加密
     *
     * @param data 需要加密的内容
     * @param key  加密密码
     * @return
     */
    public static byte[] encrypt(byte[] data, byte[] key) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, Constants.AES);
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, Constants.AES);
            Cipher cipher = Cipher.getInstance(Constants.AES_CBC_CIPHER);

            // 生成随机的IV
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedData = cipher.doFinal(data);

            // 将IV和加密数据拼接在一起
            byte[] result = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

            return result;
        } catch (Exception e) {
            throw new MybatisPlusException(e);
        }
    }

    /**
     * 解密
     *
     * @param data 待解密内容
     * @param key  解密密钥
     * @return
     */
    public static byte[] decrypt(byte[] data, byte[] key) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, Constants.AES);
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, Constants.AES);
            Cipher cipher = Cipher.getInstance(Constants.AES_CBC_CIPHER);

            // 提取IV
            byte[] iv = new byte[16];
            System.arraycopy(data, 0, iv, 0, iv.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            // 提取加密数据
            byte[] encryptedData = new byte[data.length - iv.length];
            System.arraycopy(data, iv.length, encryptedData, 0, encryptedData.length);

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new MybatisPlusException(e);
        }
    }

    /**
     * 加密
     *
     * @param data 需要加密的内容
     * @param key  加密密码
     * @return
     */
    public static String encrypt(String data, String key) {
        byte[] valueByte = encrypt(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(valueByte);
    }

    /**
     * 解密
     *
     * @param data 待解密内容 base64 字符串
     * @param key  解密密钥
     * @return
     */
    public static String decrypt(String data, String key) {
        byte[] originalData = Base64.getDecoder().decode(data.getBytes());
        byte[] valueByte = decrypt(originalData, key.getBytes(StandardCharsets.UTF_8));
        return new String(valueByte);
    }

    /**
     * 生成一个随机字符串密钥
     *
     * @return 密钥
     */
    public static String generateRandomKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16]; // 16 bytes = 128 bits
        random.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
