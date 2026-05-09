from hodlxxi_sdk import HODLXXIClient


def main() -> None:
    client = HODLXXIClient("https://hodlxxi.com")

    print("ready:", client.ready())
    print("agent_pubkey:", client.agent_manifest().get("agent_pubkey"))
    print("capability_schema:", client.capabilities().get("capability_schema"))
    print("reputation:", client.reputation())
    print("chain_health:", client.chain_health())

    job = client.create_job(
        "ping",
        {
            "source": "hodlxxi-sdk-example",
            "purpose": "sdk smoke test",
        },
    )
    print("created_job:", job)

    job_id = job.get("job_id") or job.get("id")
    if job_id:
        print("job:", client.get_job(job_id))


if __name__ == "__main__":
    main()
