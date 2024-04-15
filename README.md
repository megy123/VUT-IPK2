# VUT-IPK2

## Obsah

1. [Návrh a implementácia](#Návrh-a-implementácia)
2. [Testovanie](#Testovanie)
3. [Problémy](#Problémy)
4. [Zhrnutie](#Zhrnutie)
5. [Odkazy](#Odkazy)

## Návrh a implementácia

Návrh projektu bol rozdelený do troch celkov. Načítanie a spracovanie argumentov. Táto časť bola realizovaná pomocou funkcie getopt, ktorá spracuje požadované argumety programu. Argumenty boli dodatočne ošetrené o povinné argumenty, kde aplikácia vypíše chybové hlásenie a ukončí svoj beh. Spracovanie argumentov má na starosti funkcia parseArgs, ktorá sa nachádza v module parser.cpp. Funkcia parseArgs taktiež načítané argumenty uloží do štruktúry ArgValues_t. Táto štruktúra je predaná konštruktoru triedy Sniffer, ktorá je srdcom celej aplikácie. Konštrukor argument spracuje a informácie uloží do svojich atribútov. Druhou časťou je filtrácia. Pri spracovaní argumentov sú filtračné argumenty predané metóde getFilterString, ktorá tieto argumenty premení na string, ktorý spĺňa formuláciu pre funkciu pcap_compile. Poslednou fázou je prečítanie packetu a jeho nasledné parsovanie. Jeho prečítanie zabepečuje funkcia pcap_loop, ktorá prečíta n packetov, a predá ich callback funkcii zadanej parametrom. Táto funkcia vyexportovala z packetu všetky potrebné informácie požadované zadaním a vypísala ich na štadnardný výstup. Získavanie týchto informácií bolo kvôli prehľadnosti rozdelené do samostatných funkcií.

## Testovanie

Testovanie prebiehalo postupne po každej dokončenej časti a zároveň po napísaní celej aplikácie pre celkové otestovanie jej funkčnosti. Po prvej fáze spracovania argumentov aplikácie bola otestovaná správnosť ich výpisom na štandardný výstup. V druhej fáze bola testovaná funkčnosť len pomocou schopnosti programu prijať packet spľňujúci požadované filtre alebo pomocou chybného návratového kódu funkcie pcap_compile. Po naprogramovaní poslednej fázy bolo možné otestovať celkovú funkčnosť aplikácie. Na testovanie bola najprv použitá aplikácia netcat pre otestovanie príjímania TCP a UDP packetov a správnosť ich portov a následne bolo testované príjmanie icmp4 packetov aplikáciou ping. Keďže tieto aplikácie neboli dostatočné pre otestovanie celkovej funkčnosti tejto aplikácie, dodatočne boli použité voľne dostupné študntmi vytvorené testy a zároveň vlastný python script test.py. Tieto testy boli schopné dodatočne otestovať aj icmp6, ndp, mld a igmp packety.

## Problémy

Počas vývoja aplikácie nenastali žiadne závažnejšie problémy. Jedná sa, teda skôr o drobnosti, ktoré nebol problém vyriešiť. Medzi tieto problémy patrí primárne spracovanie ndp a mld packetov, ktoré niesu samé o sebe protokolom, ale len podmnožina icmp6. Pre vyriešnie tohto problému bolo potrebné podrobnejšie naštudovanie dokumentácie knižnice pcap. Ďalším problémom bolo spracovanie argumentov. Aplikácia vyžaduje argumenty ako v skrátenej, tiež v celej forme, o čo sa postralo prepísanie funkcie getopt na funkciu getopt_long a definovanie jej parametru option. Poslendým problémom bolo vypísanie packetu v správnej forme. Konkétne mac adries, ip adries a timespanu. Pre vypísanie mac adries a timespanu do správnej formy bola naprogramovaná vlastná funkcia. Pri ip adresách bolo nutné rozoznanie či sa jedná o ipv6 alebo ipv4.

## Zhrnutie

Po prvom projekte, ktorý bol nad mieru náročný, už neostalo toľko nových vecí k naučeniu. Najpríjemneším zážitkom bola práca s pcap knižnicou, ktorá je mimoriadne podrobne spracovaná a nebol problém dohľadať všetky potrebné informácie. Projekt taktiež ponúkol možnosť sa bližšie priučiť rôznym sieťovým protokolom a ich podskupinám. Pochopenie fungovanie ndp/mld a ich naštudovanie bolo kľúčové ich správej implementácii.

## Odkazy

[pcap library](https://www.tcpdump.org/)

[Netcat](https://nc110.sourceforge.io/)

[Python](https://www.python.org/)

[TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)

[UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)

[NDP](https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol)

[ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)

[IGMP](https://cs.wikipedia.org/wiki/Internet_Group_Management_Protocol)

[MLD](https://en.wikipedia.org/wiki/Multicast_Listener_Discovery)

[getopt](https://man7.org/linux/man-pages/man3/getopt.3.html)

[TCP/IP](https://en.wikipedia.org/wiki/Internet_protocol_suite)



