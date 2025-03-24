#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

int main() {
    int fd = open("testfile", O_WRONLY| O_CREAT, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    int flags = fcntl(fd, F_GETFL);
    printf("Parent: File access mode is O_RDWR|O_CREAT (%d %d %d)\n", flags, O_RDWR|O_CREAT, O_WRONLY|O_CREAT);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) { // Child process
        // Change file access mode
        if (fcntl(fd, F_SETFL, O_RDONLY) < 0) {
            perror("fcntl");
            return 1;
        }
        int flags = fcntl(fd, F_GETFL);
        printf("Child: Changed file access mode to O_RDONLY|.. (%d)\n", flags);
        _exit(0);
    } else { // Parent process
        sleep(2);
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0) {
            perror("fcntl");
            return 1;
        }
        if (flags & O_RDONLY) {
            printf("Parent: File access mode changed to O_RDONLY|.. (%d)\n", flags);
        } else {
            printf("Parent: File access mode is still O_RDWR|.. (%d)\n", flags);
        }
    }

    close(fd);
    return 0;
}
