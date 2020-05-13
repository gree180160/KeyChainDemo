//
//  ViewController.swift
//  KeyChainDemo
//
//  Created by WillowRivers on 2020/5/12.
//  Copyright © 2020 com.WRTechnology. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        testCrypt()
    }
    
    func testCrypt() {
        let sourceStr = "hello swift"
        let decrypStr = KeychainWrapper.threeDESEncrypt(sourceString: sourceStr)
        let result = KeychainWrapper.threeDESDecrypt(decryptStr: decrypStr)
        if result == sourceStr {
            print("success")
        }else {
            print("fail")
        }
    }
}

