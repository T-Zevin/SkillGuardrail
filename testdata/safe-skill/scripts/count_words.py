#!/usr/bin/env python3
import sys


def main() -> None:
    text = sys.stdin.read()
    print(len(text.split()))


if __name__ == "__main__":
    main()
