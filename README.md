# VURP: Ultimate ROP Processor

Florida Tech ACE 2023

## Team
| **Name** | **Email** | **Affiliation** |
| -------- | --------- | --------------- |
| Curtice Gough | cgough2019@my.fit.edu | Florida Tech |
| Joshua Hartzfeld | jhartzfeld2020@my.fit.edu | Florida Tech |
| Cody Manning | cmanning2020@my.fit.edu | Florida Tech |
| Caitlin Whitehead | ca635134@ucf.edu | University of Central Florida |
| Andres Campuzano | andres.campuzano@cromulence.com | Cromulence LLC |
| Steve Wood | steve.wood@cromulence.com | Cromulence LLC |

## Exploit Types

The sample binaries provided to us at https://github.com/tj-connor/ace-binaries contain the following vulnerabilities:

| **Exploit** | **Initial Foothold** | **Exploit Progress** | **Detection Progress** |
| ----------- | -------------------- | -------------------- | ---------------------- |
| GOT Overwrite | Format string attack (printf) | :red_circle: Not started | :yellow_circle: In progress: [3-scan-for-format-vulnerabilities](https://github.com/Curtico/vurp/tree/3-scan-for-format-vulnerabilities) |
| Printf Variable Leak | Format string attack (printf) | :red_circle: Not started | :yellow_circle: In progress: [3-scan-for-format-vulnerabilities](https://github.com/Curtico/vurp/tree/3-scan-for-format-vulnerabilities) |
| Printf Variable Write | Format string attack (printf) | :red_circle: Not started | :yellow_circle: In progress: [3-scan-for-format-vulnerabilities](https://github.com/Curtico/vurp/tree/3-scan-for-format-vulnerabilities) |
| Ret2Execve | Buffer Overflow | :red_circle: Not started | :yellow_circle: In progress: [2-scan-for-buffer-overflow-dynamically](https://github.com/Curtico/vurp/tree/2-scan-for-buffer-overflow-dynamically) |
| Ret2One | Buffer Overflow | :red_circle: Not started | :yellow_circle: In progress: [2-scan-for-buffer-overflow-dynamically](https://github.com/Curtico/vurp/tree/2-scan-for-buffer-overflow-dynamically) |
| Ret2Syscall | Buffer Overflow | :red_circle: Not started | :yellow_circle: In progress: [2-scan-for-buffer-overflow-dynamically](https://github.com/Curtico/vurp/tree/2-scan-for-buffer-overflow-dynamically) |
| Ret2System | Buffer Overflow | :red_circle: Not started | :yellow_circle: In progress: [2-scan-for-buffer-overflow-dynamically](https://github.com/Curtico/vurp/tree/2-scan-for-buffer-overflow-dynamically) |
| Ret2Win | Buffer Overflow | :red_circle: Not started | :yellow_circle: In progress: [2-scan-for-buffer-overflow-dynamically](https://github.com/Curtico/vurp/tree/2-scan-for-buffer-overflow-dynamically) |
| ROP | Buffer Overflow | :red_circle: Not started | :yellow_circle: In progress: [2-scan-for-buffer-overflow-dynamically](https://github.com/Curtico/vurp/tree/2-scan-for-buffer-overflow-dynamically) |
| Write Gadgets | Buffer Overflow | :red_circle: Not started | :yellow_circle: In progress: [2-scan-for-buffer-overflow-dynamically](https://github.com/Curtico/vurp/tree/2-scan-for-buffer-overflow-dynamically) |
| Array Index* | | :red_circle: Not started | :red_circle: Not started |

Once VURP can solve all of the standard binaries, we can see about getting the Bonus binaries solved.

<sup>*Dr. O'Connor plans to give us these, but they are not available yet.</sup>
