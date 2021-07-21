namespace ETWPM2Monitor
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.richTextBox1 = new System.Windows.Forms.RichTextBox();
            this.listView1 = new System.Windows.Forms.ListView();
            this.contextMenuStrip5 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.injectedTIDMemoryInfoToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.eTWEventPropertiesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.imageList1 = new System.Windows.Forms.ImageList(this.components);
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.contextMenuStrip2 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.contextMenuStrip3 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.fileToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.menuStrip3 = new System.Windows.Forms.MenuStrip();
            this.fileToolStripMenuItem2 = new System.Windows.Forms.ToolStripMenuItem();
            this.saveToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.actionToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.startMonitorToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.stoptMonitorToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.autoScrollToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.onToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.offToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.clearAllToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.filtersToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.allEventsIDs123ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.eventID12ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.eventID13ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.eventID23InjectionTCPIPToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.eventID1ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.eventID2ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.eventID3ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.memoryToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.injectedTIDMemoryInfoToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.eventsPropertiesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.toolStripStatusLabel1 = new System.Windows.Forms.ToolStripStatusLabel();
            this.toolStripStatusLabel2 = new System.Windows.Forms.ToolStripStatusLabel();
            this.contextMenuStrip4 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.dumpTIDToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.contextMenuStrip5.SuspendLayout();
            this.tabControl1.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.contextMenuStrip3.SuspendLayout();
            this.menuStrip3.SuspendLayout();
            this.statusStrip1.SuspendLayout();
            this.contextMenuStrip4.SuspendLayout();
            this.SuspendLayout();
            // 
            // richTextBox1
            // 
            this.richTextBox1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.richTextBox1.Location = new System.Drawing.Point(3, 3);
            this.richTextBox1.Name = "richTextBox1";
            this.richTextBox1.ReadOnly = true;
            this.richTextBox1.Size = new System.Drawing.Size(990, 372);
            this.richTextBox1.TabIndex = 0;
            this.richTextBox1.Text = "";
            // 
            // listView1
            // 
            this.listView1.ContextMenuStrip = this.contextMenuStrip5;
            this.listView1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.listView1.Location = new System.Drawing.Point(3, 3);
            this.listView1.Name = "listView1";
            this.listView1.Size = new System.Drawing.Size(990, 372);
            this.listView1.TabIndex = 1;
            this.listView1.UseCompatibleStateImageBehavior = false;
            this.listView1.SelectedIndexChanged += new System.EventHandler(this.ListView1_SelectedIndexChanged);
            // 
            // contextMenuStrip5
            // 
            this.contextMenuStrip5.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.injectedTIDMemoryInfoToolStripMenuItem,
            this.eTWEventPropertiesToolStripMenuItem});
            this.contextMenuStrip5.Name = "contextMenuStrip5";
            this.contextMenuStrip5.Size = new System.Drawing.Size(229, 48);
            // 
            // injectedTIDMemoryInfoToolStripMenuItem
            // 
            this.injectedTIDMemoryInfoToolStripMenuItem.Name = "injectedTIDMemoryInfoToolStripMenuItem";
            this.injectedTIDMemoryInfoToolStripMenuItem.Size = new System.Drawing.Size(228, 22);
            this.injectedTIDMemoryInfoToolStripMenuItem.Text = "Injected Thread Memory Info";
            this.injectedTIDMemoryInfoToolStripMenuItem.Click += new System.EventHandler(this.InjectedTIDMemoryInfoToolStripMenuItem_Click);
            // 
            // eTWEventPropertiesToolStripMenuItem
            // 
            this.eTWEventPropertiesToolStripMenuItem.Name = "eTWEventPropertiesToolStripMenuItem";
            this.eTWEventPropertiesToolStripMenuItem.Size = new System.Drawing.Size(228, 22);
            this.eTWEventPropertiesToolStripMenuItem.Text = "ETW Event Properties";
            this.eTWEventPropertiesToolStripMenuItem.Click += new System.EventHandler(this.ETWEventPropertiesToolStripMenuItem_Click);
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControl1.Location = new System.Drawing.Point(0, 24);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(1004, 404);
            this.tabControl1.TabIndex = 2;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.listView1);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(996, 378);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "ETWPM2 (Realtime events)";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.richTextBox1);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(996, 378);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "ETWPM2 (Realtime events, text)";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // imageList1
            // 
            this.imageList1.ImageStream = ((System.Windows.Forms.ImageListStreamer)(resources.GetObject("imageList1.ImageStream")));
            this.imageList1.TransparentColor = System.Drawing.Color.Transparent;
            this.imageList1.Images.SetKeyName(0, "info.ico");
            this.imageList1.Images.SetKeyName(1, "messagebox_warning.ico");
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(61, 4);
            // 
            // contextMenuStrip2
            // 
            this.contextMenuStrip2.Name = "contextMenuStrip2";
            this.contextMenuStrip2.Size = new System.Drawing.Size(61, 4);
            // 
            // contextMenuStrip3
            // 
            this.contextMenuStrip3.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem1});
            this.contextMenuStrip3.Name = "contextMenuStrip3";
            this.contextMenuStrip3.Size = new System.Drawing.Size(93, 26);
            // 
            // fileToolStripMenuItem1
            // 
            this.fileToolStripMenuItem1.Name = "fileToolStripMenuItem1";
            this.fileToolStripMenuItem1.Size = new System.Drawing.Size(92, 22);
            this.fileToolStripMenuItem1.Text = "File";
            // 
            // menuStrip3
            // 
            this.menuStrip3.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem2,
            this.actionToolStripMenuItem1,
            this.filtersToolStripMenuItem,
            this.memoryToolStripMenuItem,
            this.aboutToolStripMenuItem});
            this.menuStrip3.Location = new System.Drawing.Point(0, 0);
            this.menuStrip3.Name = "menuStrip3";
            this.menuStrip3.Size = new System.Drawing.Size(1004, 24);
            this.menuStrip3.TabIndex = 6;
            this.menuStrip3.Text = "menuStrip3";
            // 
            // fileToolStripMenuItem2
            // 
            this.fileToolStripMenuItem2.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.saveToolStripMenuItem,
            this.exitToolStripMenuItem});
            this.fileToolStripMenuItem2.Name = "fileToolStripMenuItem2";
            this.fileToolStripMenuItem2.Size = new System.Drawing.Size(37, 20);
            this.fileToolStripMenuItem2.Text = "File";
            // 
            // saveToolStripMenuItem
            // 
            this.saveToolStripMenuItem.Name = "saveToolStripMenuItem";
            this.saveToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.saveToolStripMenuItem.Text = "Save Text File";
            this.saveToolStripMenuItem.Click += new System.EventHandler(this.SaveToolStripMenuItem_Click);
            // 
            // exitToolStripMenuItem
            // 
            this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
            this.exitToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.exitToolStripMenuItem.Text = "Exit";
            this.exitToolStripMenuItem.Click += new System.EventHandler(this.ExitToolStripMenuItem_Click);
            // 
            // actionToolStripMenuItem1
            // 
            this.actionToolStripMenuItem1.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.startMonitorToolStripMenuItem,
            this.stoptMonitorToolStripMenuItem,
            this.autoScrollToolStripMenuItem,
            this.clearAllToolStripMenuItem});
            this.actionToolStripMenuItem1.Name = "actionToolStripMenuItem1";
            this.actionToolStripMenuItem1.Size = new System.Drawing.Size(54, 20);
            this.actionToolStripMenuItem1.Text = "Action";
            // 
            // startMonitorToolStripMenuItem
            // 
            this.startMonitorToolStripMenuItem.Name = "startMonitorToolStripMenuItem";
            this.startMonitorToolStripMenuItem.Size = new System.Drawing.Size(144, 22);
            this.startMonitorToolStripMenuItem.Text = "Start Monitor";
            this.startMonitorToolStripMenuItem.Click += new System.EventHandler(this.StartMonitorToolStripMenuItem_Click);
            // 
            // stoptMonitorToolStripMenuItem
            // 
            this.stoptMonitorToolStripMenuItem.Name = "stoptMonitorToolStripMenuItem";
            this.stoptMonitorToolStripMenuItem.Size = new System.Drawing.Size(144, 22);
            this.stoptMonitorToolStripMenuItem.Text = "Stop Monitor";
            this.stoptMonitorToolStripMenuItem.Click += new System.EventHandler(this.StoptMonitorToolStripMenuItem_Click);
            // 
            // autoScrollToolStripMenuItem
            // 
            this.autoScrollToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.onToolStripMenuItem,
            this.offToolStripMenuItem});
            this.autoScrollToolStripMenuItem.Name = "autoScrollToolStripMenuItem";
            this.autoScrollToolStripMenuItem.Size = new System.Drawing.Size(144, 22);
            this.autoScrollToolStripMenuItem.Text = "Auto Scroll";
            // 
            // onToolStripMenuItem
            // 
            this.onToolStripMenuItem.Name = "onToolStripMenuItem";
            this.onToolStripMenuItem.Size = new System.Drawing.Size(89, 22);
            this.onToolStripMenuItem.Text = "on";
            this.onToolStripMenuItem.Click += new System.EventHandler(this.OnToolStripMenuItem_Click);
            // 
            // offToolStripMenuItem
            // 
            this.offToolStripMenuItem.Name = "offToolStripMenuItem";
            this.offToolStripMenuItem.Size = new System.Drawing.Size(89, 22);
            this.offToolStripMenuItem.Text = "off";
            this.offToolStripMenuItem.Click += new System.EventHandler(this.OffToolStripMenuItem_Click);
            // 
            // clearAllToolStripMenuItem
            // 
            this.clearAllToolStripMenuItem.Name = "clearAllToolStripMenuItem";
            this.clearAllToolStripMenuItem.Size = new System.Drawing.Size(144, 22);
            this.clearAllToolStripMenuItem.Text = "Clear All";
            this.clearAllToolStripMenuItem.Click += new System.EventHandler(this.ClearAllToolStripMenuItem_Click);
            // 
            // filtersToolStripMenuItem
            // 
            this.filtersToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.allEventsIDs123ToolStripMenuItem,
            this.eventID12ToolStripMenuItem,
            this.eventID13ToolStripMenuItem,
            this.eventID23InjectionTCPIPToolStripMenuItem,
            this.eventID1ToolStripMenuItem,
            this.eventID2ToolStripMenuItem,
            this.eventID3ToolStripMenuItem});
            this.filtersToolStripMenuItem.Name = "filtersToolStripMenuItem";
            this.filtersToolStripMenuItem.Size = new System.Drawing.Size(50, 20);
            this.filtersToolStripMenuItem.Text = "Filters";
            // 
            // allEventsIDs123ToolStripMenuItem
            // 
            this.allEventsIDs123ToolStripMenuItem.Name = "allEventsIDs123ToolStripMenuItem";
            this.allEventsIDs123ToolStripMenuItem.Size = new System.Drawing.Size(352, 22);
            this.allEventsIDs123ToolStripMenuItem.Text = "All EventIDs 1,2,3";
            this.allEventsIDs123ToolStripMenuItem.Click += new System.EventHandler(this.AllEventsIDs123ToolStripMenuItem_Click);
            // 
            // eventID12ToolStripMenuItem
            // 
            this.eventID12ToolStripMenuItem.Name = "eventID12ToolStripMenuItem";
            this.eventID12ToolStripMenuItem.Size = new System.Drawing.Size(352, 22);
            this.eventID12ToolStripMenuItem.Text = "EventID 1,2 [NewProcess + [RemoteThreadInjection ]";
            this.eventID12ToolStripMenuItem.Click += new System.EventHandler(this.EventID12ToolStripMenuItem_Click);
            // 
            // eventID13ToolStripMenuItem
            // 
            this.eventID13ToolStripMenuItem.Name = "eventID13ToolStripMenuItem";
            this.eventID13ToolStripMenuItem.Size = new System.Drawing.Size(352, 22);
            this.eventID13ToolStripMenuItem.Text = "EventID 1,3 [NewProcess + TCPIP]";
            this.eventID13ToolStripMenuItem.Click += new System.EventHandler(this.EventID13ToolStripMenuItem_Click);
            // 
            // eventID23InjectionTCPIPToolStripMenuItem
            // 
            this.eventID23InjectionTCPIPToolStripMenuItem.Name = "eventID23InjectionTCPIPToolStripMenuItem";
            this.eventID23InjectionTCPIPToolStripMenuItem.Size = new System.Drawing.Size(352, 22);
            this.eventID23InjectionTCPIPToolStripMenuItem.Text = "EventID 2,3 [RemoteThreadInjection + TCPIP]";
            this.eventID23InjectionTCPIPToolStripMenuItem.Click += new System.EventHandler(this.EventID23InjectionTCPIPToolStripMenuItem_Click);
            // 
            // eventID1ToolStripMenuItem
            // 
            this.eventID1ToolStripMenuItem.Name = "eventID1ToolStripMenuItem";
            this.eventID1ToolStripMenuItem.Size = new System.Drawing.Size(352, 22);
            this.eventID1ToolStripMenuItem.Text = "EventID 1 [NewProcess event]";
            this.eventID1ToolStripMenuItem.Click += new System.EventHandler(this.EventID1ToolStripMenuItem_Click);
            // 
            // eventID2ToolStripMenuItem
            // 
            this.eventID2ToolStripMenuItem.Name = "eventID2ToolStripMenuItem";
            this.eventID2ToolStripMenuItem.Size = new System.Drawing.Size(352, 22);
            this.eventID2ToolStripMenuItem.Text = "EventID 2 [RemoteThreadInjection event]";
            this.eventID2ToolStripMenuItem.Click += new System.EventHandler(this.EventID2ToolStripMenuItem_Click);
            // 
            // eventID3ToolStripMenuItem
            // 
            this.eventID3ToolStripMenuItem.Name = "eventID3ToolStripMenuItem";
            this.eventID3ToolStripMenuItem.Size = new System.Drawing.Size(352, 22);
            this.eventID3ToolStripMenuItem.Text = "EventID 3 [TCPIP Send event]";
            this.eventID3ToolStripMenuItem.Click += new System.EventHandler(this.EventID3ToolStripMenuItem_Click);
            // 
            // memoryToolStripMenuItem
            // 
            this.memoryToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.injectedTIDMemoryInfoToolStripMenuItem1,
            this.toolStripSeparator1,
            this.eventsPropertiesToolStripMenuItem});
            this.memoryToolStripMenuItem.Name = "memoryToolStripMenuItem";
            this.memoryToolStripMenuItem.Size = new System.Drawing.Size(72, 20);
            this.memoryToolStripMenuItem.Text = "Properties";
            // 
            // injectedTIDMemoryInfoToolStripMenuItem1
            // 
            this.injectedTIDMemoryInfoToolStripMenuItem1.Name = "injectedTIDMemoryInfoToolStripMenuItem1";
            this.injectedTIDMemoryInfoToolStripMenuItem1.Size = new System.Drawing.Size(228, 22);
            this.injectedTIDMemoryInfoToolStripMenuItem1.Text = "Injected Thread Memory info";
            this.injectedTIDMemoryInfoToolStripMenuItem1.Click += new System.EventHandler(this.InjectedTIDMemoryInfoToolStripMenuItem1_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(225, 6);
            // 
            // eventsPropertiesToolStripMenuItem
            // 
            this.eventsPropertiesToolStripMenuItem.Name = "eventsPropertiesToolStripMenuItem";
            this.eventsPropertiesToolStripMenuItem.Size = new System.Drawing.Size(228, 22);
            this.eventsPropertiesToolStripMenuItem.Text = "ETW Events Properties";
            this.eventsPropertiesToolStripMenuItem.Click += new System.EventHandler(this.EventsPropertiesToolStripMenuItem_Click);
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripStatusLabel1,
            this.toolStripStatusLabel2});
            this.statusStrip1.Location = new System.Drawing.Point(0, 428);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(1004, 22);
            this.statusStrip1.TabIndex = 7;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            this.toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            this.toolStripStatusLabel1.Size = new System.Drawing.Size(105, 17);
            this.toolStripStatusLabel1.Text = "Monitor Status: on";
            // 
            // toolStripStatusLabel2
            // 
            this.toolStripStatusLabel2.Name = "toolStripStatusLabel2";
            this.toolStripStatusLabel2.Size = new System.Drawing.Size(47, 17);
            this.toolStripStatusLabel2.Text = "| Filters:";
            // 
            // contextMenuStrip4
            // 
            this.contextMenuStrip4.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.dumpTIDToolStripMenuItem});
            this.contextMenuStrip4.Name = "contextMenuStrip4";
            this.contextMenuStrip4.Size = new System.Drawing.Size(210, 26);
            // 
            // dumpTIDToolStripMenuItem
            // 
            this.dumpTIDToolStripMenuItem.Name = "dumpTIDToolStripMenuItem";
            this.dumpTIDToolStripMenuItem.Size = new System.Drawing.Size(209, 22);
            this.dumpTIDToolStripMenuItem.Text = "Injected TID Memory info";
            // 
            // aboutToolStripMenuItem
            // 
            this.aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            this.aboutToolStripMenuItem.Size = new System.Drawing.Size(52, 20);
            this.aboutToolStripMenuItem.Text = "About";
            this.aboutToolStripMenuItem.Click += new System.EventHandler(this.AboutToolStripMenuItem_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1004, 450);
            this.Controls.Add(this.tabControl1);
            this.Controls.Add(this.menuStrip3);
            this.Controls.Add(this.statusStrip1);
            this.Name = "Form1";
            this.Text = "ETWPM2 Events Monitor";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.Form1_FormClosed);
            this.Load += new System.EventHandler(this.Form1_Load);
            this.contextMenuStrip5.ResumeLayout(false);
            this.tabControl1.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage2.ResumeLayout(false);
            this.contextMenuStrip3.ResumeLayout(false);
            this.menuStrip3.ResumeLayout(false);
            this.menuStrip3.PerformLayout();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.contextMenuStrip4.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.ListView listView1;
        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.ImageList imageList1;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip2;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip3;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem1;
        private System.Windows.Forms.MenuStrip menuStrip3;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem2;
        private System.Windows.Forms.ToolStripMenuItem saveToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem actionToolStripMenuItem1;
        private System.Windows.Forms.ToolStripMenuItem startMonitorToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem stoptMonitorToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem clearAllToolStripMenuItem;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
        private System.Windows.Forms.ToolStripMenuItem exitToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem filtersToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem allEventsIDs123ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem eventID12ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem eventID13ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem eventID23InjectionTCPIPToolStripMenuItem;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel2;
        private System.Windows.Forms.ToolStripMenuItem eventID1ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem eventID2ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem eventID3ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem autoScrollToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem onToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem offToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip4;
        private System.Windows.Forms.ToolStripMenuItem dumpTIDToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem memoryToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip5;
        private System.Windows.Forms.ToolStripMenuItem injectedTIDMemoryInfoToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem eTWEventPropertiesToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem eventsPropertiesToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem injectedTIDMemoryInfoToolStripMenuItem1;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
        public System.Windows.Forms.RichTextBox richTextBox1;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem;
    }
}

