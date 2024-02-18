import asyncio
import configparser
from msgraph.generated.models.o_data_errors.o_data_error import ODataError
from graph import Graph

async def main():
    config = configparser.ConfigParser()
    config.read('config.ini')
    azure_settings = config['azure']
    sender = config['email']['senderEmail']
    recipient = config['email']['recipientEmail']

    graph: Graph = Graph(azure_settings)

    subject = "TEST"
    body = "test"

    try:
        await send_mail(graph, subject, body, recipient, sender)
    except ODataError as odata_error:
        print('Error:')
        if odata_error.error:
            print(odata_error.error.code, odata_error.error.message)

async def send_mail(graph: Graph, subject, body, recipient, sender):
    await graph.send_mail(subject,body,recipient,sender)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()