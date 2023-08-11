#include "blockchain/utils"

std::string bchain::utils::base58_encode(const unsigned char *input, size_t length) {
    std::string encoded;

    while (length > 0 && *input == 0) {
        encoded += '1';
        ++input;
        --length;
    }

    std::vector<unsigned char> result(length * 138 / 100 + 1);
    size_t resultIndex = result.size() - 1;

    while (length > 0) {
        unsigned int carry = *input;

        for (size_t i = result.size() - 1; i > resultIndex || carry; --i) {
            carry += 256 * result[i];
            result[i] = carry % 58;
            carry /= 58;
        }

        if (input[length - 1] == 0) {
            --length;
        } else {
            ++input;
        }
    }

    for (size_t i = 0; i < result.size() && result[i] == 0; ++i) {
        encoded += '1';
    }

    for (size_t i = resultIndex; i < result.size(); ++i) {
        encoded += base58_chars[result[i]];
    }

    return encoded;
}

// Function to decode Base58 string back to binary data
std::string bchain::utils::base58_decode(const std::string &input) {
    std::vector<unsigned char> decoded;

    size_t zeros = 0;
    while (zeros < input.size() && input[zeros] == '1') {
        ++zeros;
    }

    decoded.resize(input.size() * 733 / 1000 + 1);
    size_t decodedIndex = decoded.size() - 1;

    for (size_t i = zeros; i < input.size(); ++i) {
        unsigned int carry = base58_chars.find(input[i]);

        for (size_t j = decoded.size() - 1; j > decodedIndex || carry; --j) {
            carry += 58 * decoded[j];
            decoded[j] = carry % 256;
            carry /= 256;
        }
    }

    for (size_t i = 0; i < decoded.size() && decoded[i] == 0; ++i) {
        decoded.erase(decoded.begin());
    }

    decoded.insert(decoded.begin(), zeros, 0);

    return std::string(decoded.begin(), decoded.end());
}

std::string bchain::utils::base64_encode(const unsigned char *input, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, static_cast<int>(length));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    return result;
}

std::string bchain::utils::base64_decode(const std::string &input) {
    BIO *bio, *b64;

    std::vector<unsigned char> decodedData;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), -1);
    bio = BIO_push(b64, bio);

    char buffer[1024];
    int length = 0;

    while ((length = BIO_read(bio, buffer, sizeof(buffer))) > 0) {
        decodedData.insert(decodedData.end(), buffer, buffer + length);
    }

    BIO_free_all(bio);

    return std::string(decodedData.begin(), decodedData.end());
}