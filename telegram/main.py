from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup,InlineKeyboardButton
import pyrogram
import os
import botfunctions
import threading
import time


# bot
bot_token = os.environ.get("TOKEN", "") 
api_hash = os.environ.get("HASH", "") 
api_id = os.environ.get("ID", "")
app = Client("my_bot",api_id=api_id, api_hash=api_hash,bot_token=bot_token)
MAXSIZE = 681574400


# start command
@app.on_message(filters.command(["start"]))
def strt(client: pyrogram.client.Client, message: pyrogram.types.messages_and_media.message.Message):

    START = f'👋🏻 Hello! {message.from_user.mention}\
    \nI am a Bot based on **[VT-SCRAP](https://github.com/Brijeshkrishna/virustotal-scrapper)**\
\
    \n\n__• You can send the file to the bot or forward it from another channel, and it will check file to **[VirusTotal](http://virustotal.com/)** with over **70** different antiviruses.\
\
    \n\n• To get scan results - send me any a file up to **650 MB** in size, and you will receive a detailed analysis of it.\
\
    \n\n• With the help of a bot, you can analyse suspicious files to identify virus and other bad programs.\
\
    \n\n• You can also add me to your chats, and I will be able to analyse the files sent by participants.__'

    app.send_message(message.chat.id, START, reply_to_message_id=message.id, disable_web_page_preview=True,
    reply_markup=InlineKeyboardMarkup([[
                                           InlineKeyboardButton( "📦 Source Code", url="https://github.com/bipinkrish/VirusTotal-Bot" )
                                      ]]))


# status updater
def downstatus(statusfile,message):
    while True:
        if os.path.exists(statusfile):
            break  
    while os.path.exists(statusfile):
        with open(statusfile,"r") as upread:
            txt = upread.read()
        try:
            app.edit_message_text(message.chat.id, message.id, f"🔽 Downloaded... {txt}")
            time.sleep(10)
        except:
            time.sleep(5)


# progress function
def progress(current, total, message):
    with open(f'{message.id}downstatus.txt',"w") as fileup:
        fileup.write(f"{current * 100 / total:.1f}%")


# check function
def checkvirus(message):
    msg = app.send_message(message.chat.id, '🔽 Downloading...', reply_to_message_id=message.id)
    print(f"Downloading: ID:  {message.id}  size: {message.document.file_size}")
    dnsta = threading.Thread(target=lambda:downstatus(f'{message.id}downstatus.txt',msg),daemon=True)
    dnsta.start()

    file = app.download_media(message,progress=progress, progress_args=[message])
    os.remove(f'{message.id}downstatus.txt')
    app.edit_message_text(message.chat.id, msg.id, '🔼 Uploading to VirusTotal...')
    print(f"Uploading: ID: {message.id}  size: {message.document.file_size}")

    hash = botfunctions.uploadfile(file)
    os.remove(file)
    print(f'ID: {message.id}  HASH: {hash}')
    
    if hash == 0:
        app.edit_message_text(message.chat.id, msg.id, "✖️ Failed")
        print("HASH is 0")
        return
        
    app.edit_message_text(message.chat.id, msg.id, '⚙️ Checking...')
	print(f"Checking: ID:  {message.id}  size: {message.document.file_size}")
    maintext, checktext, signatures, link = botfunctions.cleaninfo(hash)
    
    if maintext == None:
        app.edit_message_text(message.chat.id, msg.id, "✖️ Failed")
        print("Function returned None")
        return

    app.edit_message_text(message.chat.id, msg.id, maintext,
            reply_markup=InlineKeyboardMarkup([[  
                                                    InlineKeyboardButton( "🧪 Detections", callback_data="🧪 Detections" ),
                                                    InlineKeyboardButton( "🌡 Signatures", callback_data="🌡 Signatures" ),
                                              ],
                                              [
                                                InlineKeyboardButton( "🔗 View on VirusTotal", url=link )
                                              ]]))
                                              
                                              
# document
@app.on_message(filters.document)
def docu(client: pyrogram.client.Client, message: pyrogram.types.messages_and_media.message.Message):
    if int(message.document.file_size) > MAXSIZE:
        app.send_message(message.chat.id, "⭕️ File is too Big for VirusTotal. It should be less than 650 MB", reply_to_message_id=message.id)
        return
    vt = threading.Thread(target=lambda:checkvirus(message),daemon=True)
    vt.start()	
	

# call back functon
@app.on_callback_query()
def callbck(client: pyrogram.client.Client, message: pyrogram.types.CallbackQuery):
    hash = message.message.reply_markup.inline_keyboard[1][0].url[-64:]
    action = message.data
    maintext, checktext, signatures,link = botfunctions.cleaninfo(hash)

    if action == "🔙 Back":
        app.edit_message_text(message.message.chat.id, message.message.id, maintext,
                reply_markup=InlineKeyboardMarkup([[  
                                                        InlineKeyboardButton( "🧪 Detections", callback_data="🧪 Detections" ),
                                                        InlineKeyboardButton( "🌡 Signatures", callback_data="🌡 Signatures" )
                                                ],
                                                [
                                                InlineKeyboardButton( "🔗 View on VirusTotal", url=link )
                                                ]]))

    if action == "🧪 Detections":
        app.edit_message_text(message.message.chat.id, message.message.id, checktext,
                reply_markup=InlineKeyboardMarkup([[  
                                                        InlineKeyboardButton( "🔙 Back", callback_data="🔙 Back" ),
                                                        InlineKeyboardButton( "🌡 Signatures", callback_data="🌡 Signatures" ),
                                                ],
                                                [
                                                InlineKeyboardButton( "🔗 View on VirusTotal", url=link )
                                                ]]))

    if action == "🌡 Signatures":
        app.edit_message_text(message.message.chat.id, message.message.id, signatures,
                reply_markup=InlineKeyboardMarkup([[  
                                                        InlineKeyboardButton( "🔙 Back", callback_data="🔙 Back" ),
                                                        InlineKeyboardButton( "🧪 Detections", callback_data="🧪 Detections" )
                                                ],
                                                [
                                                InlineKeyboardButton( "🔗 View on VirusTotal", url=link )
                                                ]]))
	           
    
# app run	
app.run()	
