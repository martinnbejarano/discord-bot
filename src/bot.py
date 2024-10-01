import os

import discord
from discord import Message
from dotenv import load_dotenv

from .virus_total_api import message_valid

dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(dotenv_path)
api_key = os.getenv("DISCORD_API_KEY")
        
def run_discord_bot():
    intents = discord.Intents.default()
    intents.message_content = True
    
    client = discord.Client(intents=intents)
    
    @client.event
    async def on_ready():
        print(f'{client.user} has connected to Discord!')
        
    @client.event
    async def on_message(message: Message):
        if message.author == client.user:
            return
        
        username = str(message.author)
        user_message = str(message.content)
        channel = str(message.channel)
        print(f'{username} said: {user_message} in {channel}')
        
        if not message_valid(user_message):        
            bot_message = f"Hey {username}, you can't send malicious links here."
            await message.delete()
            await message.channel.send(content=bot_message)
        
    client.run(api_key)