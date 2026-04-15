---
description: "Use when understanding what the app does, what use cases it supports, or when writing features, tests, or documentation for this project. Covers the high-level capabilities of the todo-api."
---

# Todo API — Feature Overview

A multi-user REST API for managing todo lists with collaborative editing support.

## User Accounts

- Users can register with a unique username and a password (minimum 8 characters).
- Registered users should not be able to see other users' accounts or personal information.
- A user can delete their own account.

## Authentication

- Users authenticate with their username and password to receive a session token.
- All protected operations require a valid Bearer token.
- Users can log out to invalidate their session token.

## Todo Lists

- An authenticated user can create a named todo list; they become its owner.
- A user can view all lists they own or have been invited to edit.
- A list owner can delete their list.

## Collaboration

- A list owner can invite another registered user as an editor on their list.
- Editors can view and modify todos on shared lists.
- A list owner can revoke a user's editor access at any time.
- A user cannot invite themselves as an editor.

## Todos

- Owners and editors can add todo items (with a title) to a list.
- Owners and editors can view all todos in a list, or fetch a single todo by ID.
- Owners and editors can update a todo's title and toggle its completed status.
- Owners and editors can delete a todo from a list.
