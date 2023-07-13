
#include <iostream>
#include <cstring>
#include <string>

#ifndef CPORTA

#include <ncurses.h>

int MenuScreen(const char** menuOptions, int numOptions) {
    keypad(stdscr, TRUE); // Enable keypad for special keys
    noecho(); // Disable automatic echoing of keypresses
    curs_set(0); // Hide the cursor

    int currentOption = 0; // Current selected option

    while (true) {
        // Clear the screen
        clear();

        // Calculate the center of the screen
        int centerRow = LINES / 2;
        int centerCol = COLS / 2;

        // Print the menu options
        for (int i = 0; i < numOptions; ++i) {
            if (i == currentOption) {
                // Highlight the current selected option
                attron(A_REVERSE);

                // Calculate the starting column position for center alignment
                int optionLength = std::string(menuOptions[i]).length();
                int startPos = centerCol - optionLength / 2;

                // Move the cursor to the center and print the option
                move(centerRow - numOptions / 2 + i, startPos);
                printw("%s", menuOptions[i]);

                attroff(A_REVERSE);
            } else {
                // Calculate the starting column position for center alignment
                int optionLength = std::string(menuOptions[i]).length();
                int startPos = centerCol - optionLength / 2;

                // Move the cursor to the center and print the option
                move(centerRow - numOptions / 2 + i, startPos);
                printw("%s", menuOptions[i]);
            }
        }

        // Get user input
        int key = getch();

        // Process user input
        switch (key) {
            case KEY_UP:
                // Move up in the menu
                currentOption = (currentOption - 1 + numOptions) % numOptions;
                break;
            case KEY_DOWN:
                // Move down in the menu
                currentOption = (currentOption + 1) % numOptions;
                break;
            case '\n': // Enter key
                return currentOption;
        }
    }
}

void PasswordPrompt(char* buffer, int maxLength, const char* title, bool visible) {
    if (!buffer || maxLength < 1)
        return;
    
    clear();
    noecho();

    // Calculate the center position of the screen
    int centerX = (COLS - strlen(title)) / 2;

    // Print prompt
    mvprintw(LINES / 2, centerX, "%s", title);

    // Create password input field
    char inputBuffer[maxLength + 1];  // Allocate buffer for input (one extra for null terminator)

    int ch;
    int index = 0;

    while ((ch = getch()) != '\n') {
        if (ch == KEY_BACKSPACE || ch == 127) {
            // Handle backspace key
            if (index > 0) {
                index--;
                mvprintw(LINES / 2 + 1, centerX + index, " ");
                refresh();
            }
        } else if (index < maxLength) {
            // Handle regular character input
            inputBuffer[index] = ch;
            mvprintw(LINES / 2 + 1, centerX + index, "%c", visible ? (char)ch : '*');
            refresh();
            index++;
        }
    }

    // Null-terminate the input buffer
    inputBuffer[index] = '\0';

    // Copy the input to the specified buffer location
    strncpy(buffer, inputBuffer, maxLength);
    buffer[maxLength] = '\0';  // Ensure null termination

    clear();
    refresh();

}

#endif