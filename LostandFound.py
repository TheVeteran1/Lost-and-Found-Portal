from tkinter import *
from tkinter import messagebox, ttk, filedialog
from database import *
from PIL import Image, ImageTk
import os
import io
import base64
import webbrowser
from datetime import datetime

class App:
    def __init__(self):
        init_db()
        self.show_login()
    
    def show_login(self):
        self.root = Tk()
        self.root.title("Lost & Found Portal")
        self.root.geometry("400x300")
        
        Label(self.root, text="Email:").pack(pady=5)
        self.email = Entry(self.root, width=40)
        self.email.pack(pady=5)
        
        Label(self.root, text="Password:").pack(pady=5)
        self.password = Entry(self.root, width=40, show="*")
        self.password.pack(pady=5)
        
        Button(self.root, text="Login", command=self.login).pack(pady=10)
        Button(self.root, text="Sign Up", command=self.show_signup).pack()
        
        self.root.mainloop()
    
    def show_signup(self):
        self.root.destroy()
        self.root = Tk()
        self.root.title("Sign Up")
        self.root.geometry("400x350")
        
        Label(self.root, text="Name:").pack(pady=5)
        self.name = Entry(self.root, width=40)
        self.name.pack(pady=5)
        
        Label(self.root, text="Email:").pack(pady=5)
        self.signup_email = Entry(self.root, width=40)
        self.signup_email.pack(pady=5)
        
        Label(self.root, text="Password:").pack(pady=5)
        self.signup_pass = Entry(self.root, width=40, show="*")
        self.signup_pass.pack(pady=5)
        
        Label(self.root, text="Contact:").pack(pady=5)
        self.contact = Entry(self.root, width=40)
        self.contact.pack(pady=5)
        
        Button(self.root, text="Register", command=self.register).pack(pady=10)
        Button(self.root, text="Back", command=self.back_to_login).pack()
        
        self.root.mainloop()
    
    def login(self):
        user = check_user(self.email.get(), self.password.get())
        if user:
            self.root.destroy()
            if user['is_admin']:
                AdminPortal(user)
            else:
                UserPortal(user)
        else:
            messagebox.showerror("Error", "Invalid email or password")
    
    def register(self):
        if add_user(self.name.get(), self.signup_email.get(), self.signup_pass.get(), self.contact.get()):
            messagebox.showinfo("Success", "Account created!")
            self.back_to_login()
        else:
            messagebox.showerror("Error", "Email already exists")
    
    def back_to_login(self):
        self.root.destroy()
        App()

class UserPortal:
    def __init__(self, user):
        self.user = user
        self.root = Tk()
        self.root.title(f"User Portal - {user['name']}")
        self.root.geometry("1000x700")
        self.image_references = []  # To keep references to images
        self.create_ui()
        self.root.mainloop()
    
    def create_ui(self):
        # Menu Frame
        self.menu = Frame(self.root, bg="#f0f0f0", width=200)
        self.menu.pack(side=LEFT, fill=Y)
        
        # Content Frame
        self.content = Frame(self.root)
        self.content.pack(side=RIGHT, expand=True, fill=BOTH)
        
        # Unread messages badge
        self.unread_var = StringVar()
        self.unread_var.set("")
        self.unread_label = Label(self.menu, textvariable=self.unread_var, bg="red", fg="white")
        
        self.create_menu()
        self.show_dashboard()
    
    def create_menu(self):
        # Clear existing menu
        for widget in self.menu.winfo_children():
            widget.destroy()
        
        # Menu Buttons
        buttons = [
            ("Dashboard", self.show_dashboard),
            ("Report Lost Item", [
                ("New Report", self.report_lost),
                ("My Reports", self.my_reports),
                ("Report History", self.report_history)
            ]),
            ("Found Items", [
                ("View Found Items", self.view_found),
                ("Claim Item", self.claim_item),
                ("My Claims", self.my_claims)
            ]),
            ("Messages", [
                ("New Message", self.new_message),
                ("Inbox", self.view_inbox)
            ]),
            ("My Profile", self.view_profile),
            ("Logout", self.logout)
        ]
        
        # Add unread messages badge
        unread = get_unread_count(self.user['id'])
        if unread > 0:
            self.unread_var.set(f" {unread} ")
            self.unread_label.pack(pady=5)
        
        for btn in buttons:
            if isinstance(btn[1], list):
                # Create dropdown menu
                menubtn = Menubutton(self.menu, text=btn[0], bg="#f0f0f0", relief=FLAT)
                menu1 = Menu(menubtn, tearoff=0)
                for subbtn in btn[1]:
                    menu1.add_command(label=subbtn[0], command=subbtn[1])
                menubtn.config(menu=menu1)
                menubtn.pack(fill=X, pady=2)
            else:
                Button(self.menu, text=btn[0], command=btn[1], bg="#f0f0f0", relief=FLAT, anchor="w").pack(fill=X, pady=2)
    
    def show_dashboard(self):
        self.clear_content()
        Label(self.content, text=f"Welcome {self.user['name']}!", font=("Arial", 16, "bold")).pack(pady=20)
        
        # Recent activity
        frame = Frame(self.content)
        frame.pack(pady=20, fill=X)
        
        # Recent lost items
        lost_frame = LabelFrame(frame, text="Recent Lost Items", padx=10, pady=10)
        lost_frame.pack(side=LEFT, padx=10, fill=Y)
        
        items = get_items("lost", user_id=self.user['id'])[-3:]
        if items:
            for item in items:
                Label(lost_frame, text=f"{item['name']} - {item['status']} at {item['location_name']}").pack(anchor="w")
        else:
            Label(lost_frame, text="No recent items").pack()
        
        # Recent found items
        found_frame = LabelFrame(frame, text="Recent Found Items", padx=10, pady=10)
        found_frame.pack(side=LEFT, padx=10, fill=Y)
        
        items = get_items("found")[-3:]
        if items:
            for item in items:
                Label(found_frame, text=f"{item['name']} at {item['location_name']}").pack(anchor="w")
        else:
            Label(found_frame, text="No found items").pack()
    
    def report_lost(self):
        self.clear_content()
        Label(self.content, text="Report Lost Item", font=("Arial", 16, "bold")).pack(pady=10)
        
        form_frame = Frame(self.content)
        form_frame.pack(pady=10)
        
        # Form fields
        fields = [
            ("Item Name*:", Entry(form_frame, width=40)),
            ("Category:", ttk.Combobox(form_frame, values=["Electronics", "Books", "ID Cards", "Bags", "Clothing", "Other"])),
            ("Description:", Text(form_frame, width=40, height=5)),
            ("Location Name*:", Entry(form_frame, width=40))
        ]
        
        for i, (label, widget) in enumerate(fields):
            Label(form_frame, text=label).grid(row=i, column=0, sticky="e", pady=5)
            widget.grid(row=i, column=1, pady=5)
        
        def submit():
            name = fields[0][1].get()
            location_name = fields[3][1].get()
            
            if not name:
                messagebox.showerror("Error", "Item name is required")
                return
            if not location_name:
                messagebox.showerror("Error", "Location name is required")
                return
            
            add_item(
                name=name,
                description=fields[2][1].get("1.0", END).strip(),
                category=fields[1][1].get(),
                item_type="lost",
                location_name=location_name,
                user_id=self.user['id']
            )
            messagebox.showinfo("Success", "Item reported successfully!")
            self.my_reports()
        
        Button(form_frame, text="Submit Report", command=submit).grid(row=4, columnspan=2, pady=10)
    
    def my_reports(self):
        self.clear_content()
        Label(self.content, text="My Lost Item Reports", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = get_items("lost", user_id=self.user['id'])
        
        if not items:
            Label(self.content, text="No items reported yet").pack()
            return
        
        tree = ttk.Treeview(self.content, columns=("name", "status", "date", "location"), show="headings")
        tree.heading("name", text="Item Name")
        tree.heading("status", text="Status")
        tree.heading("date", text="Date Reported")
        tree.heading("location", text="Location")
        
        for item in items:
            tree.insert("", END, values=(item['name'], item['status'], item['date'], item['location_name']))
        
        tree.pack(pady=10, padx=10, fill=BOTH, expand=True)
    
    def report_history(self):
        self.clear_content()
        Label(self.content, text="All My Reports", font=("Arial", 16, "bold")).pack(pady=10)
        
        lost_items = get_items("lost", user_id=self.user['id'])
        found_items = get_items("found", user_id=self.user['id'])
        
        if not lost_items and not found_items:
            Label(self.content, text="No reports yet").pack()
            return
        
        notebook = ttk.Notebook(self.content)
        notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Lost Items Tab
        lost_frame = Frame(notebook)
        notebook.add(lost_frame, text="Lost Items")
        
        if lost_items:
            tree = ttk.Treeview(lost_frame, columns=("name", "status", "date", "location"), show="headings")
            tree.heading("name", text="Item Name")
            tree.heading("status", text="Status")
            tree.heading("date", text="Date Reported")
            tree.heading("location", text="Location")
            
            for item in lost_items:
                tree.insert("", END, values=(item['name'], item['status'], item['date'], item['location_name']))
            
            tree.pack(fill=BOTH, expand=True)
        else:
            Label(lost_frame, text="No lost items reported").pack()
        
        # Found Items Tab
        found_frame = Frame(notebook)
        notebook.add(found_frame, text="Found Items")
        
        if found_items:
            tree = ttk.Treeview(found_frame, columns=("name", "status", "date", "location"), show="headings")
            tree.heading("name", text="Item Name")
            tree.heading("status", text="Status")
            tree.heading("date", text="Date Found")
            tree.heading("location", text="Location")
            
            for item in found_items:
                tree.insert("", END, values=(item['name'], item['status'], item['date'], item['location_name']))
            
            tree.pack(fill=BOTH, expand=True)
        else:
            Label(found_frame, text="No found items reported").pack()
    
    def view_found(self):
        self.clear_content()
        Label(self.content, text="Found Items", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = get_items("found")
        
        if not items:
            Label(self.content, text="No found items available").pack()
            return
        
        tree = ttk.Treeview(self.content, columns=("name", "date", "location"), show="headings")
        tree.heading("name", text="Item Name")
        tree.heading("date", text="Date Found")
        tree.heading("location", text="Location")
        
        for item in items:
            tree.insert("", END, values=(item['name'], item['date'], item['location_name']))
        
        tree.pack(pady=10, padx=10, fill=BOTH, expand=True)
    
    def claim_item(self):
        self.clear_content()
        Label(self.content, text="Claim Found Item", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = [item for item in get_items("found") if item['status'] == 'Unclaimed']
        
        if not items:
            Label(self.content, text="No items available for claiming").pack()
            return
        
        for item in items:
            frame = Frame(self.content, bd=1, relief=SOLID)
            frame.pack(fill=X, pady=5, padx=10)
            
            info = f"{item['name']} - Found at {item['location_name']} on {item['date']}"
            Label(frame, text=info).pack(side=LEFT, padx=5)
            
            Button(frame, text="Claim", command=lambda i=item['id']: self.process_claim(i)).pack(side=RIGHT)
    
    def process_claim(self, item_id):
        update_item_status(item_id, "Claim Pending", self.user['id'])
        messagebox.showinfo("Success", "Claim request submitted. Admin will review your claim.")
        self.my_claims()
    
    def my_claims(self):
        self.clear_content()
        Label(self.content, text="My Claims", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = [item for item in get_items("found") if item['claimed_by'] == self.user['id']]
        
        if not items:
            Label(self.content, text="No claims yet").pack()
            return
        
        for item in items:
            frame = Frame(self.content, bd=1, relief=SOLID)
            frame.pack(fill=X, pady=5, padx=10)
            
            info = f"{item['name']} - Status: {item['status']}"
            Label(frame, text=info).pack(side=LEFT, padx=5)
    
    def new_message(self):
        self.clear_content()
        Label(self.content, text="New Message", font=("Arial", 16, "bold")).pack(pady=10)
        
        frame = Frame(self.content)
        frame.pack(pady=10)
        
        # Recipient selection
        users = [u for u in get_all_users() if u['id'] != self.user['id']]
        Label(frame, text="To:").grid(row=0, column=0, sticky="e")
        self.recipient = ttk.Combobox(frame, values=[f"{u['name']} ({u['email']})" for u in users])
        self.recipient.grid(row=0, column=1, pady=5)
        
        # Message text
        Label(frame, text="Message:").grid(row=1, column=0, sticky="ne")
        self.message_text = Text(frame, width=50, height=10)
        self.message_text.grid(row=1, column=1, pady=5)
        
        def send():
            message = self.message_text.get("1.0", END).strip()
            if not message:
                messagebox.showerror("Error", "Message cannot be empty")
                return
            
            selected = self.recipient.get().split(" (")[-1].rstrip(")")
            receiver = next((u for u in users if u['email'] == selected), None)
            
            if not receiver:
                messagebox.showerror("Error", "Invalid recipient")
                return
            
            add_message(self.user['id'], receiver['id'], message)
            messagebox.showinfo("Success", "Message sent!")
            self.view_inbox()
        
        Button(frame, text="Send", command=send).grid(row=2, columnspan=2, pady=10)
    
    def view_inbox(self):
        self.clear_content()
        Label(self.content, text="Inbox", font=("Arial", 16, "bold")).pack(pady=10)
        
        conversations = get_messages(self.user['id'])
        
        if not conversations:
            Label(self.content, text="No messages yet").pack()
            return
        
        # Main container frame
        container = Frame(self.content)
        container.pack(fill=BOTH, expand=True)
        
        # Conversations list
        conv_frame = Frame(container, width=250, bg="#f0f0f0")
        conv_frame.pack(side=LEFT, fill=Y)
        
        self.conv_list = Listbox(conv_frame, width=30)
        self.conv_list.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        self.conversations = conversations
        for conv in conversations:
            display_text = f"{conv['name']}"
            if conv['unread_count'] > 0:
                display_text += f" ({conv['unread_count']})"
            self.conv_list.insert(END, display_text)
        
        # Message display area
        msg_frame = Frame(container)
        msg_frame.pack(side=RIGHT, fill=BOTH, expand=True)
        
        # Message display with scrollbar
        msg_container = Frame(msg_frame)
        msg_container.pack(fill=BOTH, expand=True)
        
        scrollbar = Scrollbar(msg_container)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        self.msg_display = Text(msg_container, wrap=WORD, state=DISABLED, yscrollcommand=scrollbar.set)
        self.msg_display.pack(fill=BOTH, expand=True)
        
        scrollbar.config(command=self.msg_display.yview)
        
        # Reply section
        reply_frame = Frame(msg_frame)
        reply_frame.pack(fill=X)
        
        self.reply_text = Text(reply_frame, height=4)
        self.reply_text.pack(fill=X)
        
        Button(reply_frame, text="Send", command=self.send_reply).pack(side=RIGHT, pady=5)
        
        # Bind conversation selection
        self.conv_list.bind("<<ListboxSelect>>", self.show_conversation)
    
    def show_conversation(self, event):
        selection = self.conv_list.curselection()
        if not selection:
            return
        
        conv = self.conversations[selection[0]]
        messages = get_messages(self.user['id'], conv['other_user_id'])
        
        self.msg_display.config(state=NORMAL)
        self.msg_display.delete(1.0, END)
        
        for msg in messages:
            timestamp = datetime.strptime(msg['timestamp'], "%Y-%m-%d %H:%M:%S").strftime("%b %d, %H:%M")
            sender = "You" if msg['sender_id'] == self.user['id'] else msg['sender_name']
            self.msg_display.insert(END, f"{sender} ({timestamp}):\n{msg['message']}\n\n")
        
        self.msg_display.config(state=DISABLED)
        self.msg_display.see(END)
        self.current_conversation = conv['other_user_id']
    
    def send_reply(self):
        if not hasattr(self, 'current_conversation'):
            messagebox.showerror("Error", "No conversation selected")
            return
        
        message = self.reply_text.get("1.0", END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty")
            return
        
        add_message(self.user['id'], self.current_conversation, message)
        self.reply_text.delete(1.0, END)
        self.show_conversation(None)  # Refresh conversation
        self.update_unread_count()
    
    def update_unread_count(self):
        unread = get_unread_count(self.user['id'])
        if unread > 0:
            self.unread_var.set(f" {unread} ")
            self.unread_label.pack()
        else:
            self.unread_var.set("")
            self.unread_label.pack_forget()
    
    def view_profile(self):
        self.clear_content()
        Label(self.content, text="My Profile", font=("Arial", 16, "bold")).pack(pady=10)
        
        frame = Frame(self.content)
        frame.pack(pady=10)
        
        # Profile picture
        self.profile_pic = None
        pic_frame = Frame(frame)
        pic_frame.grid(row=0, column=0, rowspan=4, padx=10)
        
        if self.user.get('profile_pic'):
            try:
                img = Image.open(io.BytesIO(base64.b64decode(self.user['profile_pic'])))
                img = img.resize((100, 100), Image.LANCZOS)
                self.profile_pic = ImageTk.PhotoImage(img)
                # Keep reference to prevent garbage collection
                self.image_references.append(self.profile_pic)
                Label(pic_frame, image=self.profile_pic).pack()
            except Exception as e:
                print(f"Error loading profile image: {e}")
                Label(pic_frame, text="No Image", width=15, height=5).pack()
        else:
            Label(pic_frame, text="No Image", width=15, height=5).pack()
        
        Button(pic_frame, text="Change Photo", command=self.change_photo).pack(pady=5)
        
        # User info
        Label(frame, text="Name:").grid(row=0, column=1, sticky="e")
        self.profile_name = Entry(frame)
        self.profile_name.insert(0, self.user['name'])
        self.profile_name.grid(row=0, column=2, pady=5)
        
        Label(frame, text="Email:").grid(row=1, column=1, sticky="e")
        Label(frame, text=self.user['email']).grid(row=1, column=2, sticky="w", pady=5)
        
        Label(frame, text="Contact:").grid(row=2, column=1, sticky="e")
        self.profile_contact = Entry(frame)
        self.profile_contact.insert(0, self.user.get('contact', ''))
        self.profile_contact.grid(row=2, column=2, pady=5)
        
        # Password change
        Label(frame, text="New Password:").grid(row=3, column=1, sticky="e")
        self.new_pass = Entry(frame, show="*")
        self.new_pass.grid(row=3, column=2, pady=5)
        
        Label(frame, text="Confirm Password:").grid(row=4, column=1, sticky="e")
        self.confirm_pass = Entry(frame, show="*")
        self.confirm_pass.grid(row=4, column=2, pady=5)
        
        Button(frame, text="Save Changes", command=self.save_profile).grid(row=5, columnspan=3, pady=10)
    
    def change_photo(self):
        filepath = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg *.jpeg *.png")])
        if filepath:
            try:
                with open(filepath, "rb") as f:
                    img_data = base64.b64encode(f.read()).decode('utf-8')
                update_user(self.user['id'], profile_pic=img_data)
                
                # Update displayed image
                img = Image.open(filepath)
                img = img.resize((100, 100), Image.LANCZOS)
                self.profile_pic = ImageTk.PhotoImage(img)
                # Keep reference
                self.image_references.append(self.profile_pic)
                self.view_profile()  # Refresh
                messagebox.showinfo("Success", "Profile picture updated!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update image: {str(e)}")
    
    def save_profile(self):
        name = self.profile_name.get()
        contact = self.profile_contact.get()
        new_pass = self.new_pass.get()
        confirm_pass = self.confirm_pass.get()
        
        if new_pass and new_pass != confirm_pass:
            messagebox.showerror("Error", "Passwords don't match")
            return
        
        updates = {}
        if name != self.user['name']:
            updates['name'] = name
        if contact != self.user.get('contact', ''):
            updates['contact'] = contact
        if new_pass:
            updates['password'] = new_pass
        
        if updates:
            update_user(self.user['id'], **updates)
            messagebox.showinfo("Success", "Profile updated!")
            self.user = check_user(self.user['email'], updates.get('password', self.user['password']))
        else:
            messagebox.showinfo("Info", "No changes made")
    
    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()
    
    def logout(self):
        self.root.destroy()
        App()

class AdminPortal(UserPortal):
    def __init__(self, user):
        super().__init__(user)
        self.root.title(f"Admin Portal - {user['name']}")
        self.create_menu()  # Recreate menu with admin options
    
    def create_menu(self):
        # Clear existing menu
        for widget in self.menu.winfo_children():
            widget.destroy()
        
        # Admin menu buttons
        buttons = [
            ("Dashboard", self.show_dashboard),
            ("Lost Items", [
                ("All Reports", self.all_lost_items),
                ("Pending Approval", self.pending_approval),
                ("Approved Items", self.approved_items),
                ("Rejected Items", self.rejected_items)
            ]),
            ("Found Items", [
                ("All Found Items", self.all_found_items),
                ("Pending Claims", self.pending_claims),
                ("Approved Claims", self.approved_claims)
            ]),
            ("User Management", [
                ("All Users", self.manage_users),
                ("Add New Admin", self.add_admin)
            ]),
            ("Messages", self.view_inbox),
            ("My Profile", self.view_profile),
            ("Logout", self.logout)
        ]
        
        # Add unread messages badge
        unread = get_unread_count(self.user['id'])
        if unread > 0:
            self.unread_var.set(f" {unread} ")
            self.unread_label.pack(pady=5)
        
        for btn in buttons:
            if isinstance(btn[1], list):
                # Create dropdown menu
                menubtn = Menubutton(self.menu, text=btn[0], bg="#f0f0f0", relief=FLAT)
                menu1 = Menu(menubtn, tearoff=0)
                for subbtn in btn[1]:
                    menu1.add_command(label=subbtn[0], command=subbtn[1])
                menubtn.config(menu=menu1)
                menubtn.pack(fill=X, pady=2)
            else:
                Button(self.menu, text=btn[0], command=btn[1], bg="#f0f0f0", relief=FLAT, anchor="w").pack(fill=X, pady=2)
    
    def show_dashboard(self):
        self.clear_content()
        Label(self.content, text="Admin Dashboard", font=("Arial", 16, "bold")).pack(pady=20)
        
        # Stats frames
        stats_frame = Frame(self.content)
        stats_frame.pack(pady=20)
        
        # Lost items stats
        lost_frame = LabelFrame(stats_frame, text="Lost Items", padx=10, pady=10)
        lost_frame.grid(row=0, column=0, padx=10)
        
        counts = {
            "Pending": len(get_items("lost", "pending")),
            "Approved": len(get_items("lost", "approved")),
            "Rejected": len(get_items("lost", "rejected"))
        }
        
        for i, (status, count) in enumerate(counts.items()):
            Label(lost_frame, text=f"{status}: {count}").grid(row=i, column=0, sticky="w")
        
        # Found items stats
        found_frame = LabelFrame(stats_frame, text="Found Items", padx=10, pady=10)
        found_frame.grid(row=0, column=1, padx=10)
        
        counts = {
            "Unclaimed": len(get_items("found", "Unclaimed")),
            "Pending Claims": len(get_items("found", "Claim Pending")),
            "Approved Claims": len(get_items("found", "Claimed"))
        }
        
        for i, (status, count) in enumerate(counts.items()):
            Label(found_frame, text=f"{status}: {count}").grid(row=i, column=0, sticky="w")
        
        # User stats
        user_frame = LabelFrame(stats_frame, text="Users", padx=10, pady=10)
        user_frame.grid(row=0, column=2, padx=10)
        
        users = get_all_users()
        Label(user_frame, text=f"Total Users: {len(users)}").grid(row=0, column=0, sticky="w")
        Label(user_frame, text=f"Admins: {sum(1 for u in users if u['is_admin'])}").grid(row=1, column=0, sticky="w")
    
    def all_lost_items(self):
        self.clear_content()
        Label(self.content, text="All Lost Items", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = get_items("lost")
        
        if not items:
            Label(self.content, text="No lost items reported").pack()
            return
        
        tree = ttk.Treeview(self.content, columns=("name", "status", "reported_by", "date", "location"), show="headings")
        tree.heading("name", text="Item Name")
        tree.heading("status", text="Status")
        tree.heading("reported_by", text="Reported By")
        tree.heading("date", text="Date")
        tree.heading("location", text="Location")
        
        for item in items:
            with get_db() as db:
                user = db.execute("SELECT name FROM users WHERE id=?", (item['user_id'],)).fetchone()
            tree.insert("", END, values=(item['name'], item['status'], user['name'], item['date'], item['location_name']))
        
        tree.pack(pady=10, padx=10, fill=BOTH, expand=True)
    
    def pending_approval(self):
        self.clear_content()
        Label(self.content, text="Pending Approval", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = [item for item in get_items("lost") if item['status'] == 'pending']
        
        if not items:
            Label(self.content, text="No items pending approval").pack()
            return
        
        for item in items:
            frame = Frame(self.content, bd=1, relief=SOLID)
            frame.pack(fill=X, pady=5, padx=10)
            
            with get_db() as db:
                user = db.execute("SELECT name FROM users WHERE id=?", (item['user_id'],)).fetchone()
            
            info = f"{item['name']} - Reported by {user['name']} at {item['location_name']} on {item['date']}"
            Label(frame, text=info).pack(side=LEFT, padx=5)
            
            Button(frame, text="Approve", command=lambda i=item['id']: self.update_item_status(i, "approved")).pack(side=RIGHT)
            Button(frame, text="Reject", command=lambda i=item['id']: self.update_item_status(i, "rejected")).pack(side=RIGHT)
    
    def update_item_status(self, item_id, status):
        update_item_status(item_id, status)
        self.pending_approval()  # Refresh the view

    def approved_items(self):
        self.clear_content()
        Label(self.content, text="Approved Items", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = [item for item in get_items("lost") if item['status'] == 'approved']
        
        if not items:
            Label(self.content, text="No approved items").pack()
            return
        
        tree = ttk.Treeview(self.content, columns=("name", "reported_by", "date", "location"), show="headings")
        tree.heading("name", text="Item Name")
        tree.heading("reported_by", text="Reported By")
        tree.heading("date", text="Date")
        tree.heading("location", text="Location")
        
        for item in items:
            with get_db() as db:
                user = db.execute("SELECT name FROM users WHERE id=?", (item['user_id'],)).fetchone()
            tree.insert("", END, values=(item['name'], user['name'], item['date'], item['location_name']))
        
        tree.pack(pady=10, padx=10, fill=BOTH, expand=True)

    def rejected_items(self):
        self.clear_content()
        Label(self.content, text="Rejected Items", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = [item for item in get_items("lost") if item['status'] == 'rejected']
        
        if not items:
            Label(self.content, text="No rejected items").pack()
            return
        
        tree = ttk.Treeview(self.content, columns=("name", "reported_by", "date", "location", "reason"), show="headings")
        tree.heading("name", text="Item Name")
        tree.heading("reported_by", text="Reported By")
        tree.heading("date", text="Date")
        tree.heading("location", text="Location")
        tree.heading("reason", text="Reason")
        
        for item in items:
            with get_db() as db:
                user = db.execute("SELECT name FROM users WHERE id=?", (item['user_id'],)).fetchone()
            tree.insert("", END, values=(item['name'], user['name'], item['date'], item['location_name'], item.get('rejection_reason', '')))
        
        tree.pack(pady=10, padx=10, fill=BOTH, expand=True)

    def all_found_items(self):
        self.clear_content()
        Label(self.content, text="All Found Items", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = get_items("found")
        
        if not items:
            Label(self.content, text="No found items available").pack()
            return
        
        tree = ttk.Treeview(self.content, columns=("name", "status", "found_by", "date", "location"), show="headings")
        tree.heading("name", text="Item Name")
        tree.heading("status", text="Status")
        tree.heading("found_by", text="Found By")
        tree.heading("date", text="Date Found")
        tree.heading("location", text="Location")
        
        for item in items:
            with get_db() as db:
                user = db.execute("SELECT name FROM users WHERE id=?", (item['user_id'],)).fetchone()
            tree.insert("", END, values=(
                item['name'],
                item['status'],
                user['name'],
                item['date'],
                item['location_name']
            ))
        
        tree.pack(pady=10, padx=10, fill=BOTH, expand=True)

    def pending_claims(self):
        self.clear_content()
        Label(self.content, text="Pending Claims", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = [item for item in get_items("found") if item['status'] == 'Claim Pending']
        
        if not items:
            Label(self.content, text="No pending claims").pack()
            return
        
        for item in items:
            frame = Frame(self.content, bd=1, relief=SOLID)
            frame.pack(fill=X, pady=5, padx=10)
            
            with get_db() as db:
                found_by = db.execute("SELECT name FROM users WHERE id=?", (item['user_id'],)).fetchone()
                claimed_by = db.execute("SELECT name FROM users WHERE id=?", (item['claimed_by'],)).fetchone()
            
            info = f"{item['name']} - Found at {item['location_name']} by {found_by['name']}, Claimed by {claimed_by['name']}"
            Label(frame, text=info).pack(side=LEFT, padx=5)
            
            Button(frame, text="Approve", command=lambda i=item['id']: self.approve_claim(i)).pack(side=RIGHT)
            Button(frame, text="Reject", command=lambda i=item['id']: self.reject_claim(i)).pack(side=RIGHT)

    def approve_claim(self, item_id):
        update_item_status(item_id, "Claimed")
        messagebox.showinfo("Success", "Claim approved!")
        self.pending_claims()

    def reject_claim(self, item_id):
        update_item_status(item_id, "Unclaimed", claimed_by=None)
        messagebox.showinfo("Success", "Claim rejected!")
        self.pending_claims()

    def approved_claims(self):
        self.clear_content()
        Label(self.content, text="Approved Claims", font=("Arial", 16, "bold")).pack(pady=10)
        
        items = [item for item in get_items("found") if item['status'] == 'Claimed']
        
        if not items:
            Label(self.content, text="No approved claims").pack()
            return
        
        tree = ttk.Treeview(self.content, columns=("name", "found_by", "claimed_by", "date", "location"), show="headings")
        tree.heading("name", text="Item Name")
        tree.heading("found_by", text="Found By")
        tree.heading("claimed_by", text="Claimed By")
        tree.heading("date", text="Date")
        tree.heading("location", text="Location")
        
        for item in items:
            with get_db() as db:
                found_by = db.execute("SELECT name FROM users WHERE id=?", (item['user_id'],)).fetchone()
                claimed_by = db.execute("SELECT name FROM users WHERE id=?", (item['claimed_by'],)).fetchone()
            tree.insert("", END, values=(
                item['name'],
                found_by['name'],
                claimed_by['name'],
                item['date'],
                item['location_name']
            ))
        
        tree.pack(pady=10, padx=10, fill=BOTH, expand=True)

    def manage_users(self):
        self.clear_content()
        Label(self.content, text="User Management", font=("Arial", 16, "bold")).pack(pady=10)
        
        users = get_all_users()
        
        if not users:
            Label(self.content, text="No users found").pack()
            return
        
        tree = ttk.Treeview(self.content, columns=("name", "email", "contact", "role"), show="headings")
        tree.heading("name", text="Name")
        tree.heading("email", text="Email")
        tree.heading("contact", text="Contact")
        tree.heading("role", text="Role")
        
        for user in users:
            role = "Admin" if user['is_admin'] else "User"
            tree.insert("", END, values=(
                user['name'],
                user['email'],
                user.get('contact', ''),
                role
            ))
        
        tree.pack(pady=10, padx=10, fill=BOTH, expand=True)

    def add_admin(self):
        self.clear_content()
        Label(self.content, text="Add New Admin", font=("Arial", 16, "bold")).pack(pady=10)
        
        frame = Frame(self.content)
        frame.pack(pady=10)
        
        Label(frame, text="Select User:").grid(row=0, column=0, sticky="e")
        users = [u for u in get_all_users() if not u['is_admin']]
        self.admin_select = ttk.Combobox(frame, values=[f"{u['name']} ({u['email']})" for u in users])
        self.admin_select.grid(row=0, column=1, pady=5)
        
        def promote():
            selected = self.admin_select.get().split(" (")[-1].rstrip(")")
            user = next((u for u in users if u['email'] == selected), None)
            
            if not user:
                messagebox.showerror("Error", "Invalid user selection")
                return
            
            update_user(user['id'], is_admin=True)
            messagebox.showinfo("Success", f"{user['name']} is now an admin!")
            self.manage_users()
        
        Button(frame, text="Promote to Admin", command=promote).grid(row=1, columnspan=2, pady=10)

if __name__ == "__main__":
    App()

    
