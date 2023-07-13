#ifndef CONSINT_H
#define CONSINT_H

int MenuScreen(const char** menuOptions, int numOptions);

void PasswordPrompt(char* dst, int inputMaxLen, const char* title, bool visible = false);

#endif