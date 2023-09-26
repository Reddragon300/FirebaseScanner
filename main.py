#!/usr/bin/python

import sys
import os
import ntpath
import re
import hashlib
import argparse
import logging
import requests
import json
from apktool import decode as apktool_decode
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor


class bcolors:
    TITLE = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    INFO = '\033[93m'
    OKRED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BGRED = '\033[41m'
    UNDERLINE = '\033[4m'
    FGWHITE = '\033[37m'
    FAIL = '\033[95m'


class Configuration:
    def __init__(self):
        self.rootDir: str = os.path.expanduser("~") + "/.SourceCodeAnalyzer/"
        self.projectDir: str = ""
        self.apkFilePath: str = ""
        self.apkFileName: str = ""
        self.firebaseProjectList: List[str] = []
        self.apktoolPath: str = "./Dependencies/apktool_2.8.1.jar"


class Firebase:
    __cache = {}

    @staticmethod
    def isSecure(firebase_project: str) -> bool:
        if firebase_project not in Firebase.__cache:
            url: str = f'https://{firebase_project}.firebaseio.com/.json'
            try:
                response: requests.Response = requests.get(url)
                Firebase.__cache[firebase_project] = response.status_code == 401
            except requests.exceptions.RequestException as err:
                Firebase.__cache[firebase_project] = False

        return Firebase.__cache[firebase_project]


class FirebaseScanner:
    def __init__(self, apk_file_path=None, firebase_projects=None):
        self.configuration = Configuration()
        self.configuration.apkFilePath = apk_file_path
        self.configuration.firebaseProjectList = (
            firebase_projects.split(",") if firebase_projects else []
        )

        # Configure the logging system
        log_format: str = "%(asctime)s [%(levelname)s]: %(message)s"
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        log_file = os.path.join(log_dir, "firebase_scanner.log")
        logging.basicConfig(filename=log_file,
                            level=logging.INFO, format=log_format)

    def isNewInstallation(self) -> bool:
        if not os.path.exists(self.configuration.rootDir):
            myPrint("Thank you for installing Firebase Scanner!", "MESSAGE")
            os.mkdir(self.configuration.rootDir)
            return True
        return False

    def validateAPKPath(self) -> None:
        while True:
            self.configuration.apkFilePath = input(
                "Enter the path to the APK file: ")
            if os.path.exists(self.configuration.apkFilePath):
                myPrint("APK File Found.", "INFO")
                self.configuration.apkFileName = ntpath.basename(
                    self.configuration.apkFilePath)
                break
            else:
                myPrint(
                    "Incorrect APK file path. Please try again with the correct file name.", "ERROR")
                sys.exit(1)

    def decompileAPK(self) -> str:
        myPrint("Initiating APK Decompilation Process.", "INFO")
        project_dir = os.path.join(
            self.configuration.rootDir, f"{self.configuration.apkFileName}_{hashlib.md5().hexdigest()}")

        if os.path.exists(project_dir):
            myPrint(
                "The same APK is already decompiled. Skipping decompilation and proceeding with scanning application.", "INFO")
            return project_dir

        # Decompile the APK file if it has not already been decompiled.
        os.mkdir(project_dir)
        myPrint("Decompiling the APK file using APKtool.", "INFO")

        try:
            apktool_decode(self.configuration.apkFilePath,
                           project_dir, force=True)
        except Exception as e:
            myPrint(
                f"Apktool failed with error: {str(e)}. Please try again.", "ERROR")
            sys.exit(1)

        myPrint("Successfully decompiled the application. Proceeding with enumerating Firebase project names from the application code.", "INFO")
        return project_dir

    def findFirebaseProjectNames(self) -> None:
        # Regex to find Firebase project names in the decompiled APK file.
        regex: str = r'https*://((?:[a-zA-Z0-9\-_]+\.)*[a-zA-Z]{2,})\.firebaseio\.com'
        for dir_path, dirs, file_names in os.walk(os.path.join(self.configuration.rootDir, f"{self.configuration.apkFileName}_{hashlib.md5().hexdigest()}")):
            for file_name in file_names:
                full_path: str = os.path.join(dir_path, file_name)
                try:
                    with open(full_path, 'r', errors='ignore') as file:
                        for line in file:
                            temp: List[str] = re.findall(regex, line)
                            if temp:
                                self.configuration.firebaseProjectList.extend(
                                    temp)
                                myPrint("Firebase Instance(s) Found", "INFO")
                except FileNotFoundError:
                    myPrint(f"File not found: {full_path}", "ERROR")
                except PermissionError:
                    myPrint(f"Permission denied: {full_path}", "ERROR")
                except Exception as e:
                    myPrint(
                        f"Error opening file {full_path}: {str(e)}", "ERROR")
        if not self.configuration.firebaseProjectList:
            myPrint("No Firebase Project Found. Exiting.", "OUTPUT")
            sys.exit(0)

    def printFirebaseProjectNames(self) -> None:
        myPrint(f"Found {len(self.configuration.firebaseProjectList)} Project References in the application. Printing the list of Firebase Projects found.", "OUTPUT")
        for project_name in self.configuration.firebaseProjectList:
            myPrint(project_name, "OUTPUT_WS")

    def scanFirebaseInstance(self, firebase_project: str) -> None:
        url: str = f'https://{firebase_project}.firebaseio.com/.json'
        try:
            response: requests.Response = requests.get(url)
            if response.status_code == 401:
                myPrint(
                    f"Secure Firebase Instance Found: {firebase_project}", "SECURE")
            elif response.status_code == 404:
                myPrint(
                    f"Project does not exist: {firebase_project}", "OUTPUT_WS")
            else:
                myPrint(
                    f"Unable to identify misconfiguration for: {firebase_project}", "OUTPUT_WS")
        except requests.exceptions.RequestException as err:
            myPrint(
                f"Error accessing Firebase instance: {firebase_project}", "OUTPUT_WS")

    def scanFirebase(self) -> None:
        myPrint("Scanning Firebase Instance(s)", "INFO")
        try:
            with ThreadPoolExecutor(max_workers=4) as executor:
                for firebase_project in self.configuration.firebaseProjectList:
                    executor.submit(self.scanFirebaseInstance,
                                    firebase_project)
            print()
        except Exception as e:
            myPrint(f"Error scanning Firebase instances: {str(e)}", "ERROR")
            sys.exit(1)

    def run(self) -> None:
        if self.isNewInstallation():
            try:
                load_config(self.configuration)
                self.validateAPKPath()
                decompiled_dir = self.decompileAPK()
                self.findFirebaseProjectNames()
                self.scanFirebase()
            except Exception as e:
                myPrint(f"Error: {str(e)}", "ERROR")
                sys.exit(1)

        total_instances = len(self.configuration.firebaseProjectList)
        secure_count: int = len(
            [p for p in self.configuration.firebaseProjectList if Firebase.isSecure(p)])
        insecure_count: int = total_instances - secure_count
        myPrint("Scan Summary:", "MESSAGE")
        myPrint(f"Total Firebase Instances Found: {total_instances}", "INFO")
        myPrint(f"Secure Firebase Instances Found: {secure_count}", "SECURE")
        myPrint(
            f"Misconfigured Firebase Instances Found: {insecure_count}", "INSECURE_WS")
        myPrint("Thank You For Using Firebase Scanner", "INFO")

        try:
            save_config(self.configuration)
        except Exception as e:
            myPrint(f"Error saving configuration: {str(e)}", "ERROR")


def myPrint(text: str, type: str) -> None:
    """
    Print text to the console with color formatting.

    Args:
        text (str): The text to print.
        type (str): The type of message, which determines the color formatting.
    """
    color_codes: Dict[str, str] = {
        "INFO": bcolors.INFO,
        "ERROR": bcolors.BGRED + bcolors.FGWHITE + bcolors.BOLD,
        "MESSAGE": bcolors.TITLE + bcolors.BOLD,
        "INSECURE_WS": bcolors.OKRED + bcolors.BOLD,
        "OUTPUT": bcolors.OKBLUE + bcolors.BOLD,
        "OUTPUT_WS": bcolors.OKBLUE + bcolors.BOLD,
        "SECURE": bcolors.OKGREEN + bcolors.BOLD,
    }
    logging_func = getattr(logging, type.lower(), logging.info)
    logging_func(text)
    print(color_codes.get(type, "") + text + bcolors.ENDC)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Firebase Scanner: Analyze Firebase usage in Android apps."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--apk",
        metavar="APK_FILE",
        type=str,
        help="Path to the APK file for analysis.",
    )
    group.add_argument(
        "--projects",
        metavar="PROJECT_NAMES",
        type=str,
        help="Comma-separated list of Firebase project names.",
    )

    args = parser.parse_args()

    if args.apk:
        apk_file_path = args.apk
        firebase_scanner = FirebaseScanner(apk_file_path)
    elif args.projects:
        firebase_projects = args.projects
        firebase_scanner = FirebaseScanner(firebase_projects=firebase_projects)

    firebase_scanner.run()
