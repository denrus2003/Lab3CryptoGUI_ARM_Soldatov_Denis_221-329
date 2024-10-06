import SwiftUI
import Security

class SecureEnclaveManager: ObservableObject {
    @Published var decryptedString: String = ""
    private var privateKey: SecKey?
    private var encryptedDataStore: [Data] = []

    init() {
        generateSecureEnclaveKey()
        storeEncryptedStrings()
    }

    // Генерация ключа в Secure Enclave
    func generateSecureEnclaveKey() {
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: "com.example.securestorage.mykey",
                kSecAttrAccessControl as String: access
            ]
        ]

        var error: Unmanaged<CFError>?
        privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        
        if let error = error {
            print("Ошибка при создании ключа в Secure Enclave: \(error.takeRetainedValue())")
        } else {
            print("Ключ успешно создан в Secure Enclave.")
        }
    }

    // Шифрование данных с использованием публичного ключа
    func encrypt(data: Data) -> Data? {
        guard let publicKey = SecKeyCopyPublicKey(privateKey!) else {
            print("Не удалось получить публичный ключ.")
            return nil
        }

        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
        
        if SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) {
            var error: Unmanaged<CFError>?
            if let encryptedData = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) {
                print("Данные успешно зашифрованы.")
                return encryptedData as Data
            } else {
                print("Ошибка шифрования: \(error!.takeRetainedValue().localizedDescription)")
            }
        } else {
            print("Алгоритм шифрования не поддерживается.")
        }
        return nil
    }

    // Дешифрование данных с использованием приватного ключа
    func decrypt(encryptedData: Data) -> Data? {
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
        
        var error: Unmanaged<CFError>?
        if let decryptedData = SecKeyCreateDecryptedData(privateKey!, algorithm, encryptedData as CFData, &error) {
            print("Данные успешно расшифрованы.")
            return decryptedData as Data
        } else {
            print("Ошибка дешифрования: \(error!.takeRetainedValue().localizedDescription)")
        }
        return nil
    }

    // Сохранение зашифрованных строк в массив
    func storeEncryptedStrings() {
        let originalStrings = [
            "Быстрая коричневая лиса прыгает через ленивую собаку.",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            "В криптографии шифрование — это процесс кодирования сообщений или информации таким образом, чтобы их могли прочитать только авторизованные стороны.",
            "История криптографии насчитывает тысячи лет, одним из первых и самых простых методов шифрования был шифр Цезаря.",
            "Современная криптография основана на сложных математических алгоритмах, таких как RSA и AES, которые обеспечивают безопасную связь через интернет.",
            "Шифрование данных жизненно важно для защиты конфиденциальной информации в современном цифровом мире, особенно в условиях роста кибератак.",
            "Криптография с открытым ключом основывается на парах ключей: открытом ключе, который можно передавать публично, и закрытом ключе, который должен оставаться в секрете.",
            "Технология блокчейн использует криптографические методы для обеспечения безопасности и неизменности транзакций.",
            "Квантовые вычисления рассматриваются как угроза и возможность для криптографии.",
            "Специалисты по кибербезопасности должны постоянно адаптироваться к новым угрозам."
        ]

        for string in originalStrings {
            if let data = string.data(using: .utf8), let encryptedData = encrypt(data: data) {
                encryptedDataStore.append(encryptedData)
                print("Строка зашифрована и сохранена.")
            } else {
                print("Ошибка шифрования строки.")
            }
        }
    }

    // Запрос расшифрованной строки по индексу
    func getDecryptedString(at index: Int) -> String? {
        guard index < encryptedDataStore.count else {
            print("Неверный индекс.")
            return nil
        }

        let encryptedData = encryptedDataStore[index]
        if let decryptedData = decrypt(encryptedData: encryptedData),
           let decryptedString = String(data: decryptedData, encoding: .utf8) {
            return decryptedString
        } else {
            print("Ошибка при расшифровке строки.")
            return nil
        }
    }

    // Количество зашифрованных данных
    func getEncryptedDataCount() -> Int {
        return encryptedDataStore.count
    }

    // Запрос расшифрованной строки по индексу и вывод результата
    func decryptData(at index: Int) {
        if let decrypted = getDecryptedString(at: index) {
            decryptedString = decrypted
        } else {
            decryptedString = "Ошибка при расшифровке."
        }
    }
}

struct ContentView: View {
    @StateObject private var manager = SecureEnclaveManager()
    @State private var inputIndex: String = ""

    var body: some View {
        VStack {
            Text("Введите индекс для расшифровки (от 0 до \(manager.getEncryptedDataCount() - 1)):")
                .padding()

            TextField("Введите индекс", text: $inputIndex)
                .padding()

            Button(action: {
                if let index = Int(inputIndex), index >= 0 && index < manager.getEncryptedDataCount() {
                    manager.decryptData(at: index)
                } else {
                    manager.decryptedString = "Неверный индекс"
                }
            }) {
                Text("Расшифровать")
            }
            .padding()

            Text(manager.decryptedString)
                .padding()
                .multilineTextAlignment(.center)
        }
        .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
