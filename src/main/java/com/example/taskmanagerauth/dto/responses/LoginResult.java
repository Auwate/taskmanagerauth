package com.example.taskmanagerauth.dto.responses;

public sealed interface LoginResult permits Success, MfaRequired, TotpRequired {}
