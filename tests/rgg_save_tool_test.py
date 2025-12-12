import os
import unittest
from unittest.mock import mock_open, patch

from rgg_save_tool.rgg_save_tool import (
    calculate_checksum_y6,
    crc32_checksum,
    decrypt_data,
    encrypt_data,
    find_game_abbreviation,
    game_headers,
    game_keys,
    identify_game_from_save,
    main,
    process_file,
)


class RGGSaveToolTests(unittest.TestCase):
    encrypted_file = "saves/test.sav"
    decrypted_file = "saves/test_ik_ik.json"
    converted_file = "test_converted.sav"

    @patch("sys.argv", ["rgg_save_tool.py", "saves/test_ik.json"])
    @patch("rgg_save_tool.rgg_save_tool.process_file")
    def test_encrypt_end_to_end(self, mock_process):
        main()
        self.assertTrue(mock_process.called)

    @patch("sys.argv", ["rgg_save_tool.py", "saves/test_ik.sav"])
    @patch("rgg_save_tool.rgg_save_tool.process_file")
    def test_decrypt_end_to_end(self, mock_process):
        main()
        self.assertTrue(mock_process.called)

    @patch(
        "sys.argv",
        [
            "rgg_save_tool.py",
            "saves/test_ik.sav",
            "test_converted.sav",
            "-g",
            "ik",
            "--ishin-to-gamepass",
        ],
    )
    @patch("rgg_save_tool.rgg_save_tool.process_file")
    def test_ik_to_gamepass_end_to_end(self, mock_process):
        main()
        self.assertTrue(mock_process.called)

    @classmethod
    def tearDownClass(self):
        for file in [self.encrypted_file, self.decrypted_file, self.converted_file]:
            if os.path.exists(file):
                os.remove(file)


class TestEncryptData(unittest.TestCase):
    def test_ik_game(self):
        data = bytes.fromhex("00000000000000000000000000000000")
        expected_length = len(data)
        encrypted_data = encrypt_data("ik", data)

        self.assertEqual(len(encrypted_data), len(data))
        self.assertEqual(len(encrypted_data), 16)

        calculated_checksum = crc32_checksum(data[:-16])
        embedded_checksum = int.from_bytes(encrypted_data[-8:-4], "little")
        self.assertEqual(embedded_checksum, calculated_checksum)

        self.assertEqual(encrypted_data[-16:], data[-16:])

    def test_y6_game(self):
        data = b"testdata"
        encrypted_data = encrypt_data("y6", data)
        self.assertEqual(len(encrypted_data), len(data) + 4)

    def test_other_games(self):
        for game in game_keys.keys():
            if game not in ["ik", "y6"]:
                data = b"testdata"
                encrypted_data = encrypt_data(game, data)
                self.assertEqual(len(encrypted_data), len(data) + 4)

    def test_unsupported_game(self):
        with self.assertRaises(SystemExit):
            encrypt_data("unsupported_game", b"testdata")


class TestDecryptData(unittest.TestCase):
    def test_ik_game(self):
        encrypted_data = b"encrypted data for ik"
        decrypted_data = decrypt_data("ik", encrypted_data)
        self.assertIsNotNone(decrypted_data)

    def test_y6_game(self):
        encrypted_data = b"encrypted data for y6"
        decrypted_data = decrypt_data("y6", encrypted_data)
        self.assertIsNotNone(decrypted_data)

    def test_unsupported_game(self):
        with self.assertRaises(SystemExit):
            decrypt_data("unsupported_game", b"testdata")


class TestProcessFile(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data=b'{"test": "data"}')
    def test_process_file_encrypt(self, mock_file):
        process_file("test_y6.json", "y6")
        mock_file.assert_called_with("test.sav", "wb")

    @patch("builtins.open", new_callable=mock_open)
    def test_process_file_decrypt(self, mock_file):
        encrypted_data = encrypt_data("y6", b'{"test": "data"}')
        mock_file.return_value.read.return_value = encrypted_data
        process_file("test.sav", "y6")
        mock_file.assert_called_with("test_y6.json", "wb")


class TestGameSaveIdentification(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open)
    def test_file_is_a_game_save(self, mock_file):
        for game, headers in game_headers.items():
            if game == "yk2R":
                continue
            for header in headers:
                read_data = header + b"remaining_data"
                mock_file.return_value.read.return_value = read_data
                self.assertEqual(identify_game_from_save("fake_file"), game)

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_exit_when_file_not_found(self, mock_file):
        with self.assertRaises(SystemExit):
            identify_game_from_save("nonexistent_file")


class TestFindGameAbbreviation(unittest.TestCase):
    def test_game_abbr_in_command_line(self):
        result = find_game_abbreviation("test_file_ik.json", "ik")
        self.assertEqual(result, "ik")

    def test_game_abbr_in_filename(self):
        result = find_game_abbreviation("test_file_lj.sav")
        self.assertEqual(result, "lj")

    @patch("sys.exit", side_effect=lambda x=1: (_ for _ in ()).throw(SystemExit(x)))
    @patch("rgg_save_tool.rgg_save_tool.identify_game_from_save", return_value=False)
    def test_failed_detection(self, mock_identify, mock_exit):
        with self.assertRaises(SystemExit) as cm:
            find_game_abbreviation("test_file.sav")
        self.assertEqual(cm.exception.code, 1)


class TestConvertIshinSave(unittest.TestCase):
    input_bytes = bytes.fromhex("00000000000000000000000000000000")

    @patch("builtins.open", new_callable=mock_open, read_data=input_bytes)
    def test_convert_to_steam(self, mock_file):
        output_bytes = bytes.fromhex("00000000210000000000000000000000")
        process_file("input.sys", "ik", ishin_to_steam=True)
        mock_file.assert_called_with("input_ik.json", "wb")
        mock_file().write.assert_called_once_with(output_bytes)

    @patch("builtins.open", new_callable=mock_open, read_data=input_bytes)
    def test_convert_to_gamepass(self, mock_file):
        output_bytes = bytes.fromhex("000000008F0000000000000000000000")
        process_file("input.sys", "ik", ishin_to_gamepass=True)
        mock_file.assert_called_with("input_ik.json", "wb")
        mock_file().write.assert_called_once_with(output_bytes)

    @patch("builtins.open", new_callable=mock_open, read_data=input_bytes)
    def test_default_output_file(self, mock_file):
        output_filename = "output.ext"
        output_bytes = bytes.fromhex("00000000210000000000000000000000")
        process_file(
            "input.sys", "ik", ishin_to_steam=True, output_file=output_filename
        )
        mock_file.assert_called_with(output_filename, "wb")
        mock_file().write.assert_called_once_with(output_bytes)


class TestCalculateChecksumY6(unittest.TestCase):
    def test_checksum_calculation(self):
        data = b"testdata"
        checksum = calculate_checksum_y6(data)
        self.assertIsInstance(checksum, int)
        self.assertGreaterEqual(checksum, 0)
