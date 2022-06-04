# 탐지 기반 안티 탬퍼
  

## 목적
기존 패커형 안티탬퍼가 뚫리는 가장 큰 원인은 자유롭게 크래킹을 시도할 수 있는 것이다.
탐지 기반 안티 탬퍼는 보호하는 어플리케이션의 실행 환경을 미리 검사하고 유저를 밴할 수 있는 감시 서버와 연동하여 이런 시도를 막는다.

## 개발 환경

* Visual studio 2022
* 윈도우 10 64bit

## 의존성

없음

## 구성 요소

* Client.DLL - 
* Backend.exe - 서버 프로그램.

## 빌드 방법

VS2022을 사용하여 빌드한다
## 적용 방법

Client.DLL을 보호 받고 싶은 어플리케이션에서 로드한다.   
이 후 별도의 쓰레드로 구동시킨다.  
**C++ 프로그램은 TestApplication 참고**  

## Contact

bank2014@naver.com


## License

```
The MIT License (MIT)

Copyright (c) 2021 yoonleeverse

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

```
