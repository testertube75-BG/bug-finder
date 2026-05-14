from pyrogram import Client


def main() -> None:
    print("Telegram STRING_SESSION generator")
    print("Use only your own Telegram account. Never share the generated string.")
    api_id = int(input("API_ID: ").strip())
    api_hash = input("API_HASH: ").strip()

    with Client("music_user", api_id=api_id, api_hash=api_hash) as app:
        print("\nSTRING_SESSION:")
        print(app.export_session_string())
        print("\nKeep this secret. Put it in your .env file, never in public GitHub.")


if __name__ == "__main__":
    main()
