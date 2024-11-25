# 프로젝트 소개 
kaist에서 제공하는 교육용 OS Pintos를 통해 OS의 핵심기능을 구현한 프로젝트입니다. 
# 참여 인원 
### 크래프톤 정글 6기 수료생 일부 ( 10명 규모 )

# 세부 내용
### 1. Thread 
- Thread 구현
- timmer interrupt를 통한 스케줄링 구현, RR (Round Robin)방식 적용
- 우선순위 스케줄링을 poriority로 구현, Donation 기능 포함
- lock, semaphore 구현

### 2. System Call 
- 10가지 이상의 System Call 구현 ( fork, write, read, ..etc )
- thread와 process 구분
  
### 3. Virtual memory 
- User Stack 구현
- page fault 및 lazy load 구현
- fork시 User Stack 복사 기능 구현 


