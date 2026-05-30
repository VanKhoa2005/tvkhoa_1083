class PlayFairCipher:
    def __init__(self):
        pass

    def create_playfair_matrix(self, key):
        key = key.replace("J", "I")
        key = key.upper()

        key_set = set()
        clean_key = ""

        for char in key:
            if char.isalpha() and char not in key_set:
                clean_key += char
                key_set.add(char)

        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

        matrix_chars = list(clean_key)

        for letter in alphabet:
            if letter not in key_set:
                matrix_chars.append(letter)
                key_set.add(letter)

            if len(matrix_chars) == 25:
                break

        playfair_matrix = [
            matrix_chars[i:i + 5]
            for i in range(0, len(matrix_chars), 5)
        ]

        return playfair_matrix

    def find_letter_coords(self, matrix, letter):
        letter = letter.replace("J", "I")

        for row in range(len(matrix)):
            for col in range(len(matrix[row])):
                if matrix[row][col] == letter:
                    return row, col

        return None

    def prepare_plain_text(self, plain_text):
        plain_text = plain_text.replace("J", "I")
        plain_text = plain_text.upper()

        clean_text = ""

        for char in plain_text:
            if char.isalpha():
                clean_text += char

        result = ""
        i = 0

        while i < len(clean_text):
            first = clean_text[i]

            if i + 1 < len(clean_text):
                second = clean_text[i + 1]

                if first == second:
                    result += first + "X"
                    i += 1
                else:
                    result += first + second
                    i += 2
            else:
                result += first + "X"
                i += 1

        return result

    def playfair_encrypt(self, plain_text, matrix):
        plain_text = self.prepare_plain_text(plain_text)
        encrypted_text = ""

        for i in range(0, len(plain_text), 2):
            pair = plain_text[i:i + 2]

            row1, col1 = self.find_letter_coords(matrix, pair[0])
            row2, col2 = self.find_letter_coords(matrix, pair[1])

            if row1 == row2:
                encrypted_text += matrix[row1][(col1 + 1) % 5]
                encrypted_text += matrix[row2][(col2 + 1) % 5]

            elif col1 == col2:
                encrypted_text += matrix[(row1 + 1) % 5][col1]
                encrypted_text += matrix[(row2 + 1) % 5][col2]

            else:
                encrypted_text += matrix[row1][col2]
                encrypted_text += matrix[row2][col1]

        return encrypted_text

    def playfair_decrypt(self, cipher_text, matrix):
        cipher_text = cipher_text.upper()
        decrypted_text = ""

        for i in range(0, len(cipher_text), 2):
            pair = cipher_text[i:i + 2]

            row1, col1 = self.find_letter_coords(matrix, pair[0])
            row2, col2 = self.find_letter_coords(matrix, pair[1])

            if row1 == row2:
                decrypted_text += matrix[row1][(col1 - 1) % 5]
                decrypted_text += matrix[row2][(col2 - 1) % 5]

            elif col1 == col2:
                decrypted_text += matrix[(row1 - 1) % 5][col1]
                decrypted_text += matrix[(row2 - 1) % 5][col2]

            else:
                decrypted_text += matrix[row1][col2]
                decrypted_text += matrix[row2][col1]

        plain_text = ""

        for i in range(len(decrypted_text)):
            if (
                i > 0
                and i < len(decrypted_text) - 1
                and decrypted_text[i] == "X"
                and decrypted_text[i - 1] == decrypted_text[i + 1]
            ):
                continue

            plain_text += decrypted_text[i]

        if plain_text.endswith("X"):
            plain_text = plain_text[:-1]

        return plain_text