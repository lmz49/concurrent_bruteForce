/**
    @mainpage bruteForceHash.cpp
    @file
    @brief This program allows the user to input a 4-5 character length password, gets an MD5 hash, and then uses concurrency to brute-force that hash.
    @authod Lauren Zarro
    @date June 11, 2024
**/

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <openssl/evp.h>
#include <atomic>
#include <algorithm>

/**
 * @brief Computes the MD5 hash of the given content using OpenSSL EVP.
 * @param content The string to hash.
 * @return A string representing the hash of the input.
 * @section Source: https://stackoverflow.com/questions/7860362/how-can-i-use-openssl-md5-in-c-to-hash-a-string
 */
std::string md5(const std::string& content) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_md5();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    std::string output;

    EVP_DigestInit_ex2(context, md, NULL);
    EVP_DigestUpdate(context, content.c_str(), content.length());
    EVP_DigestFinal_ex(context, md_value, &md_len);
    EVP_MD_CTX_free(context);

    output.resize(md_len * 2);
    for (unsigned int i = 0; i < md_len; ++i) {
        std::sprintf(&output[i * 2], "%02x", md_value[i]);
    }
    return output;
}

std::queue<std::string> guess_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;
std::atomic<bool> done_producing(false);
std::atomic<bool> password_found(false);
std::string found_password = "";

/**
 * @brief Generates all possible password guesses of a given length using the provided character set.
 * @param charset The set of characters to use for generating guesses.
 * @param length The length of the password guesses.
 */
void generate_guesses(const std::string& charset, int length) {
    int charset_size = charset.size();
    int total_guesses = 1;
    for (int i = 0; i < length; ++i) {
        total_guesses *= charset_size;
    }

    for (int i = 0; i < total_guesses; ++i) {
        std::string guess(length, ' ');
        int temp = i;
        for (int j = 0; j < length; ++j) {
            guess[j] = charset[temp % charset_size];
            temp /= charset_size;
        }

        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            guess_queue.push(guess);
        }
        queue_cv.notify_one();
    }

    done_producing = true;
    queue_cv.notify_all();
}

/**
 * @brief Consumer function that processes password guesses from the queue and compares them to the target hash.
 * @param hashedPassword The target hash to compare guesses against.
 */
void process_guesses(const std::string& hashedPassword) {
    while (!password_found) {
        std::string guess;

        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, []{ return !guess_queue.empty() || done_producing; });

            if (!guess_queue.empty()) {
                guess = guess_queue.front();
                guess_queue.pop();
            } else if (done_producing) {
                break;
            }
        }

        if (!guess.empty() && md5(guess) == hashedPassword) {
            password_found = true;
            std::lock_guard<std::mutex> found_guard(queue_mutex);
            found_password = guess;
            queue_cv.notify_all();
            break;
        }
    }
}

/**
 * @brief Main brute-force function that initializes producer and consumer threads.
 * @param charset The set of characters to use for generating guesses.
 * @param length The length of the password guesses.
 * @param hashedPassword The target hash to compare guesses against.
 */
void brute_force_password(const std::string& charset, int length, const std::string& hashedPassword) {
    std::thread producer(generate_guesses, charset, length);

    int num_threads = std::thread::hardware_concurrency();
    std::vector<std::thread> consumers;
    for (int i = 0; i < num_threads; ++i) {
        consumers.emplace_back(process_guesses, std::ref(hashedPassword));
    }

    producer.join();
    for (auto& consumer : consumers) {
        consumer.join();
    }

    if (password_found) {
        std::cout << "Password found: " << found_password << std::endl;
    } else {
        std::cout << "Password not found." << std::endl;
    }
}

/**
 * @brief Main function to prompt user for a password and initiate brute-force guessing.
 * @param argc Argument count.
 * @param argv Argument values.
 * @return int Exit status of the program.
 */
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <password>" << std::endl;
        return 1;
    }

    std::string password = argv[1];

    if (password.length() < 4 || password.length() > 5) {
        std::cerr << "Invalid password length. Password must be 4-5 characters." << std::endl;
        return 1;
    }

    std::string hashedPassword = md5(password);
    std::cout << "Original password: " << password << std::endl;
    std::cout << "Hashed password: " << hashedPassword << std::endl;

    std::string charset;
    if (std::all_of(password.begin(), password.end(), ::isdigit)) {
        charset = "0123456789";
    } else {
        charset = "abcdefghijklmnopqrstuvwxyz";
    }

    int password_length = password.length();

    brute_force_password(charset, password_length, hashedPassword);

    return 0;
}
