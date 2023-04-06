/***********************************************************************************************************************
 * Copyright 2022 Younis Khalil
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 **********************************************************************************************************************/
#include <iostream>
#include <pkw/exceptions.h>
#include <pkw/pkw.h>
#include <pkw/pprf_aead_pkw.h>
void print(const std::vector<unsigned char> &v) {
    for (auto val: v)
        std::cout << val;
}

int main() {
    // Construct a new PKW abject with fresh randomness and tag-lenth 256, key-length 196
    PPRF_AEAD_PKW pkw(256, 196);

    // Define a header and a key to be wrapped
    std::vector<unsigned char> header({0, 2, 'a', 'b'});
    std::vector<unsigned char> key({
            's',
            'e',
            'n',
            's',
            1,
            't',
            1,
            'v',
            'e',
    });

    int tag = 12;
    // Wrap the key using the tag and the header
    std::vector<unsigned char> wrapped_key = pkw.wrap(tag, header, key);

    std::cout << "The ciphertext produced after wrapping key = ";
    print(key);
    std::cout << " with header = ";
    print(header);
    std::cout << " and tag = " << tag << ":" << std::endl;
    print(wrapped_key);
    std::cout << std::endl;

    // Unwrapping with a different tag or header will lead to an error
    try {
        pkw.unwrap(11, header, wrapped_key);
    } catch (PuncturableKeyWrappingException &e) {
        std::cout << "Unwrapping with a wrong tag fails." << std::endl;
    }
    try {
        std::vector<unsigned char> other_header({0, 2, 'a', 'b', 'c'});
        pkw.unwrap(tag, other_header, wrapped_key);
    } catch (UnwrappingException &e) {
        std::cout << "Unwrapping with a wrong header fails." << std::endl;
    }

    // Unwrap with the correct parameters:
    std::vector<unsigned char> unwrapped_key = pkw.unwrap(tag, header, wrapped_key);
    std::cout << "Unwrapping reveals the original key: ";
    print(unwrapped_key);
    std::cout << std::endl;

    // Puncturing a tag
    pkw.punc(tag);
    std::cout << "Punctured on tag = " << tag << std::endl;

    // Now wrapping and unwrapping using the tag will fail
    try {
        pkw.unwrap(tag, header, wrapped_key);
    } catch (PuncturableKeyWrappingException &e) {
        std::cout << "Unwrapping with a punctured tag fails." << std::endl;
    }
    try {
        pkw.wrap(tag, header, key);
    } catch (PuncturableKeyWrappingException &e) {
        std::cout << "Wrapping with a punctured tag fails." << std::endl;
    }

    // To offload the key for storage it can be serialized
    SecureByteBuffer serialized_pkw = pkw.serializeKey();

    // It can also be protected by a password derived key
    SecureByteBuffer serialized_encrypted_pkw = pkw.serializeAndEncryptKey("securepassword");

    // Deserialization is handled by a factory, which constructs a shared pointer to the object
    auto deserialized = PPRF_AEAD_PKW_Factory().fromSerialized(serialized_pkw);
    auto deserialized_with_password = PPRF_AEAD_PKW_Factory().fromSerializedAndEncrypted(serialized_encrypted_pkw, "securepassword");

    //  Wrapping and unwrapping using the tag will still fail
    try {
        deserialized->unwrap(tag, header, wrapped_key);
    } catch (PuncturableKeyWrappingException &e) {
        std::cout << "Unwrapping with a punctured tag fails after export and import." << std::endl;
    }
    try {
        deserialized_with_password->wrap(tag, header, key);
    } catch (PuncturableKeyWrappingException &e) {
        std::cout << "Wrapping with a punctured tag fails after export and import." << std::endl;
    }
}