#pragma once

enum UserViolationLevel {
	Trivial, // 경고 - 클라이언트에 경고 pop up을 띄우고 프로그램을 종료함
	Moderate, // 밴 - 이 수준이면 바로 밴
	Severe // 우회행위가 감지된 유저 - 일단 Moderate와 똑같은 처리
};

void AddUserToBanList()
{
	// blacklist 파일이 없으면 생성
	// blacklist 파일에 해당 유저 uuid 기록
}

bool CheckBan()
{
	// file에 기록된 uuid와 일치한지 확인 -> if yes return true 
}

