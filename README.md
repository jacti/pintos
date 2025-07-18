<h1>[Project 1] Thread 완료</h1>
<hr>
<h2>설명 :</h2>
<p>Pintos 1주차 Thread의 모든 요구사항을 구현하여 테스트를 전부 통과한 코드입니다.</p>
<hr>
<h2>구현된 기능:</h2>
<ul>
<li>sleep 개선
<ul>
<li>busy-wait 방식으로 동작하던 timer_sleep을 block 방식으로 개선</li>
</ul>
</li>
<li>priority scheduling 구현
<ul>
<li>기존 FIFO 방식의 scheduling 을 priority를 반영한 RR으로 변경</li>
</ul>
</li>
<li>priority donation 구현
<ul>
<li>lock에서 기다려야할 때 holder에게 현재 쓰레드의 우선순위를 기부</li>
</ul>
</li>
<li>MLFQS 구현
<ul>
<li>4.4 BSD 방식으로 MLFQS 구현</li>
</ul>
</li>
</ul>
<hr>
<h2>통과한 테스트 :</h2>

 <p align="center">
  <img src="https://github.com/user-attachments/assets/f2a70809-97b2-4020-8a4d-365998da7c14" width="300" height="700" style="object-fit: contain;"  alt="make check" />
  <img src="https://github.com/user-attachments/assets/0c9be4d3-da49-442b-8df2-9e9ffdbd9b71" width="300"  height="700" style="object-fit: contain;" alt="select_test.sh" />
</p>

Test Name | Category | Result | Description
-- | -- | -- | --
alarm-single | sleep 개선 | Pass | 단일 스레드의 timer_sleep 깨우기를 테스트합니다.
alarm-multiple | sleep 개선 | Pass | 서로 다른 기간 동안 대기하는 여러 스레드를 테스트합니다.
alarm-simultaneous | sleep 개선 | Pass | 동일한 틱에서 동시에 깨우기를 테스트합니다.
alarm-priority | sleep 개선 | Pass | 깨우기가 스레드 우선순위를 준수하는지 확인합니다.
alarm-zero | sleep 개선 | Pass | sleep(0)에서 즉시 반환되는지 검증합니다.
alarm-negative | sleep 개선 | Pass | 음수 대기에 대해 즉시 반환되는지 검증합니다.
priority-change | priority scheduling 구현 | Pass | 스레드 우선순위의 동적 변경을 테스트합니다.
priority-fifo | priority scheduling 구현 | Pass | FIFO 락 순서를 사용하는 스케줄링을 테스트합니다.
priority-preempt | priority scheduling 구현 | Pass | 높은 우선순위 스레드에 의한 선점을 테스트합니다.
priority-sema | priority scheduling 구현 | Pass | 세마포어와 우선순위 상호작용을 테스트합니다.
priority-condvar | priority scheduling 구현 | Pass | 조건 변수와 우선순위 상호작용을 테스트합니다.
priority-donate-one | priority donation 구현 | Pass | 단일 수준 우선순위 기부를 테스트합니다.
priority-donate-multiple | priority donation 구현 | Pass | 락 간 중첩된 우선순위 기부를 테스트합니다.
priority-donate-multiple2 | priority donation 구현 | Pass | 여러 기부자로부터의 기부를 테스트합니다.
priority-donate-nest | priority donation 구현 | Pass | 중첩된 기부 시나리오를 테스트합니다.
priority-donate-sema | priority donation 구현 | Pass | 세마포어 연산을 통한 기부를 테스트합니다.
priority-donate-lower | priority donation 구현 | Pass | 낮은 우선순위 락 소유자에 대한 기부를 테스트합니다.
priority-donate-chain | priority donation 구현 | Pass | 여러 락을 통한 연쇄 기부를 테스트합니다.
mlfqs-load-1 | MLFQS 구현 | Pass | 1초 후 load_avg 업데이트를 검증합니다.
mlfqs-load-60 | MLFQS 구현 | Pass | 60초 후 load_avg 업데이트를 검증합니다.
mlfqs-load-avg | MLFQS 구현 | Pass | 시간 경과에 따른 올바른 load_avg 계산을 확인합니다.
mlfqs-recent-1 | MLFQS 구현 | Pass | 한 틱 후 recent_cpu 계산을 검증합니다.
mlfqs-fair-2 | MLFQS 구현 | Pass | 두 개의 경쟁 스레드 간 공정성을 테스트합니다.
mlfqs-fair-20 | MLFQS 구현 | Pass | 20개의 경쟁 스레드 간 공정성을 테스트합니다.
mlfqs-nice-2 | MLFQS 구현 | Pass | nice=2가 MLFQS에서 우선순위를 조정하는지 확인합니다.
mlfqs-nice-10 | MLFQS 구현 | Pass | nice=10이 MLFQS에서 우선순위를 조정하는지 확인합니다.
mlfqs-block | MLFQS 구현 | Pass | 차단된 스레드가 지표에서 제외되는지 확인합니다.


<hr>
<h2>참조 :</h2>
<p><a href="https://www.notion.so/Project-1-232c9595474e808cb8e7d022e6f2c5b7?pvs=21">Project 1 회고</a></p>
<hr>
