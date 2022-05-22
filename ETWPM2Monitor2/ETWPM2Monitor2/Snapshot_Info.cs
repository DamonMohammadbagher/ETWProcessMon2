using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static ETWPM2Monitor2.Form1;

namespace ETWPM2Monitor2
{
    class Snapshot_Info
    {
        public static object[] _ETWPM2InjectionTab_SnapshotTab_LoadSnapshot()
        {
           
            object[] _return_obj = new object[2];
            string targetfile = "";
            OpenFileDialog ofd = new OpenFileDialog();

            try
            {
                try
                {
                    ofd.Filter = "data files (ETWPM2InjectionSnapshot*.idata)|*.idata";
                    ofd.FilterIndex = 0;
                    ofd.ShowDialog();
                }
                catch (Exception)
                {

                }

                targetfile = ofd.FileName;
                string loadstring = "";
                using (StreamReader Snapshot = new StreamReader(targetfile))
                {
                    loadstring = Snapshot.ReadToEnd();
                    Snapshot.Close();
                }

                int[] allindex = Memory_info._FindAllIndex("listviewitem", loadstring, 0);

                ListViewItem[] __ilist = new ListViewItem[allindex.Length];
                string[] items = null;
                Int32 count = 0;

                foreach (int xitem in allindex)
                {
                    try
                    {
                        ListViewItem tmp = new ListViewItem();
                        string[] error_and_payload = new string[25];

                        Thread.Sleep(100);

                        items = loadstring.Substring(xitem + 17).Split('\n')[0].Split('@');
                        error_and_payload = loadstring.Substring(xitem + 17).Split('\n');
                        bool error = false;
                        string payload = "";

                        if (error_and_payload[24].Contains("_____________________________error____________")) error = true;

                        for (int i = 0; i < error_and_payload.Length; i++)
                        {
                            if (!error)
                            {
                                payload += error_and_payload[i + 2] + "\n";
                                if (i >= 48) break;
                            }
                            else
                            {
                                payload += error_and_payload[i + 2] + "\n";
                                if (i >= 23) break;
                            }
                        }

                        tmp.SubItems.Add(items[1]);
                        tmp.SubItems.Add(items[2]);
                        tmp.SubItems.Add(items[3]);
                        tmp.SubItems.Add(items[4]);
                         
                        object objx = tmp.Clone();

                        __ilist[count] = (ListViewItem)objx;
                        __ilist[count].Name = payload;

                        count++;

                    }
                    catch (Exception)
                    {

                    }
                }

                _return_obj[0] = __ilist;
                _return_obj[1] = targetfile;

                return _return_obj;

            }
            catch (Exception ee)
            {
                MessageBox.Show(ee.Message);
                return null;
            }
            
        }
        public static void _ETWPM2InjectionTab_TakeSnapshot(ListView Target_listview)
        {
            try
            {
                string date = DateTime.Now.Year + "_" + DateTime.Now.Month + "_" + DateTime.Now.Day + "_" + DateTime.Now.Hour + "."
                    + DateTime.Now.Minute + "." + DateTime.Now.Second;

                StringBuilder sb = new StringBuilder();
                ListViewItem[] list = Target_listview.Items.Cast<ListViewItem>().ToArray();

                Int32 index = 0;

                foreach (ListViewItem item in list)
                {
                    object objx = item.Clone();
                    sb.AppendLine("ListViewItems:[" + index.ToString() + "] " + item.SubItems[0].Text + "@" + item.SubItems[1].Text + "@"
                    + item.SubItems[2].Text + "@" + item.SubItems[3].Text + "@" + item.SubItems[4].Text + "\n[#payload_data]\n" + item.Name.ToString() + "\n");

                    index++;
                }

                using (StreamWriter Snapshot = new StreamWriter("ETWPM2InjectionSnapshot" + date + ".idata"))
                {
                    Snapshot.Write(sb.ToString());
                    Snapshot.Close();

                }

                MessageBox.Show("Snapshot Data saved into file: \n\n" + "1. ETWPM2InjectionSnapshot" + date + ".idata" + ")\n");
            }
            catch (Exception ee)
            {
                MessageBox.Show(ee.Message);
            }
        }
        public static void _ProcessesTab_TakeSnapshot(TreeView Target_nodes1 , TreeView Target_nodes2)
        {
            try
            {
                string date = DateTime.Now.Year + "_" + DateTime.Now.Month + "_" + DateTime.Now.Day + "_" + DateTime.Now.Hour + "."
                    + DateTime.Now.Minute + "." + DateTime.Now.Second;

                using (Stream Snapshot = File.Open("LiveProcessSnapshot" + date + ".data", FileMode.Create))
                {
                    BinaryFormatter _data = new BinaryFormatter();
                    _data.Serialize(Snapshot, Target_nodes1.Nodes.Cast<TreeNode>().ToList());
                }

                using (Stream Snapshot = File.Open("ClosedProcessSnapshot" + date + ".data2", FileMode.Create))
                {
                    BinaryFormatter _data = new BinaryFormatter();
                    _data.Serialize(Snapshot, Target_nodes2.Nodes.Cast<TreeNode>().ToList());
                }

                MessageBox.Show("Snapshot Data saved into 2 files: \n\n" + "1. LiveProcessSnapshot" + date + ".data" + "\n\n2. " + "ClosedProcessSnapshot" + date + ".data2");
            }
            catch (Exception ee)
            {

                MessageBox.Show(ee.Message);
            }
        }
        public static object[] _ProcessesTab_Snapshot1Tab_LoadSnapshot()
        {
            object[] _return_obj = new object[4];
            try
            {
                
                OpenFileDialog ofd = new OpenFileDialog();
                try
                {
                    ofd.Filter = "data files (LiveProcessSnapshot*.data)|*.data";
                    ofd.FilterIndex = 0;
                    ofd.ShowDialog();
                }
                catch (Exception)
                {


                }

                string targetfile = ofd.FileName;
               
                using (Stream file = File.Open(targetfile, FileMode.Open))
                {
                    BinaryFormatter _data = new BinaryFormatter();
                    object obj = _data.Deserialize(file);

                    TreeNode[] _Nodes = (obj as IEnumerable<TreeNode>).ToArray();
                    //treeView4.Nodes.AddRange(_Nodes);
                    _return_obj[0] = _Nodes;
                }

                OpenFileDialog ofd2 = new OpenFileDialog();

                ofd2.Filter = "data2 files (ClosedProcessSnapshot*.data2)|*.data2";
                ofd2.FilterIndex = 0;
                ofd2.ShowDialog();
                string targetfile2 = ofd2.FileName;

                using (Stream file = File.Open(targetfile2, FileMode.Open))
                {
                    BinaryFormatter _data = new BinaryFormatter();
                    object obj = _data.Deserialize(file);

                    TreeNode[] _Nodes = (obj as IEnumerable<TreeNode>).ToArray();
                    //treeView5.Nodes.AddRange(_Nodes);
                    _return_obj[1] = _Nodes;
                }

                _return_obj[2] = targetfile;
                _return_obj[3] = targetfile2;
                return _return_obj;                

            }
            catch (Exception ee)
            {

                MessageBox.Show(ee.Message);
            }
           
            return _return_obj;
        }


        //public void _ETWPM2InjectionTab_SnapshotTab_LoadSnapshot()
        //{
        //    try
        //    {
        //        listView9.Items.Clear();

        //        OpenFileDialog ofd = new OpenFileDialog();

        //        ofd.Filter = "data files (ETWPM2InjectionSnapshot*.idata)|*.idata";
        //        ofd.FilterIndex = 0;
        //        ofd.ShowDialog();
        //        string targetfile = ofd.FileName;

        //        using (StreamReader Snapshot = new StreamReader(targetfile))
        //        {
        //            string loadstring = Snapshot.ReadToEnd();
        //            Snapshot.Close();
        //            int [] allindex = Memory_info._FindAllIndex("listviewitem", loadstring, 0);

        //            ListViewItem __ilist = new ListViewItem();
        //            string[] items = null;
        //            foreach (int xitem in allindex)
        //            {
        //                try
        //                {

        //                    __ilist = new ListViewItem();
        //                    string[] error_and_payload = new string[25];

        //                    Thread.Sleep(100);

        //                    items = loadstring.Substring(xitem + 17).Split('\n')[0].Split('@');
        //                    error_and_payload = loadstring.Substring(xitem + 17).Split('\n');
        //                    bool error = false;
        //                    string payload = "";

        //                    if (error_and_payload[24].Contains("_____________________________error____________")) error = true;

        //                    for (int i = 0; i < error_and_payload.Length; i++)
        //                    {
        //                        if (!error)
        //                        {
        //                            payload += error_and_payload[i + 2] + "\n";
        //                            if (i >= 48) break;
        //                        }
        //                        else
        //                        {
        //                            payload += error_and_payload[i + 2] + "\n";
        //                            if (i >= 23) break;
        //                        }
        //                    }

        //                    __ilist.SubItems.Add(items[1]);
        //                    __ilist.SubItems.Add(items[2]);
        //                    __ilist.SubItems.Add(items[3]);
        //                    __ilist.SubItems.Add(items[4]);
        //                    __ilist.Name = payload;

        //                    listView9.Items.Add(__ilist);

        //                }
        //                catch (Exception)
        //                {

        //                }
        //            }                   

        //        }

        //        Thread.Sleep(100);
        //        tabControl1.SelectedIndex = 2;
        //        Thread.Sleep(10);
        //        toolStripStatusLabel8.Text = targetfile;

        //        MessageBox.Show("Data files loaded in Snapshot Tab \n" + targetfile);

        //    }
        //    catch (Exception ee)
        //    {
        //        MessageBox.Show(ee.Message);
        //    }
        //}
        //public void _ETWPM2InjectionTab_TakeSnapshot()
        //{
        //    try
        //    {
        //        string date = DateTime.Now.Year + "_" + DateTime.Now.Month + "_" + DateTime.Now.Day + "_" + DateTime.Now.Hour + "."
        //            + DateTime.Now.Minute + "." + DateTime.Now.Second;

        //        StringBuilder sb = new StringBuilder();
        //        ListViewItem[] list = listView5.Items.Cast<ListViewItem>().ToArray();
        //        Int32 index = 0;

        //        foreach (ListViewItem item in list)
        //        {
        //            object objx = item.Clone();
        //            sb.AppendLine("ListViewItems:[" + index.ToString() + "] " + item.SubItems[0].Text + "@" + item.SubItems[1].Text + "@"
        //            + item.SubItems[2].Text + "@" + item.SubItems[3].Text + "@" + item.SubItems[4].Text + "\n[#payload_data]\n" + item.Name.ToString() + "\n");

        //            index++;
        //        }

        //        using (StreamWriter Snapshot = new StreamWriter("ETWPM2InjectionSnapshot" + date + ".idata"))
        //        {
        //            Snapshot.Write(sb.ToString());
        //            Snapshot.Close();

        //        }

        //        MessageBox.Show("Snapshot Data saved into file: \n\n" + "1. ETWPM2InjectionSnapshot" + date + ".idata" + ")\n");
        //    }
        //    catch (Exception ee)
        //    {
        //        MessageBox.Show(ee.Message);
        //    }
        //}
        //public void _ProcessesTab_TakeSnapshot()
        //{
        //    try
        //    {
        //        string date = DateTime.Now.Year + "_" + DateTime.Now.Month + "_" + DateTime.Now.Day + "_" + DateTime.Now.Hour + "."
        //            + DateTime.Now.Minute + "." + DateTime.Now.Second;

        //        using (Stream Snapshot = File.Open("LiveProcessSnapshot" + date + ".data", FileMode.Create))
        //        {
        //            BinaryFormatter _data = new BinaryFormatter();
        //            _data.Serialize(Snapshot, treeView1.Nodes.Cast<TreeNode>().ToList());
        //        }

        //        using (Stream Snapshot = File.Open("ClosedProcessSnapshot" + date + ".data2", FileMode.Create))
        //        {
        //            BinaryFormatter _data = new BinaryFormatter();
        //            _data.Serialize(Snapshot, treeView2.Nodes.Cast<TreeNode>().ToList());
        //        }

        //        MessageBox.Show("Snapshot Data saved into 2 files: \n\n" + "1. LiveProcessSnapshot" + date + ".data" + "\n\n2. " + "ClosedProcessSnapshot" + date + ".data2");
        //    }
        //    catch (Exception ee)
        //    {

        //        MessageBox.Show(ee.Message);
        //    }
        //}
        //public void _ProcessesTab_Snapshot1Tab_LoadSnapshot()
        //{
        //    try
        //    {
        //        treeView4.Nodes.Clear();
        //        treeView5.Nodes.Clear();

        //        OpenFileDialog ofd = new OpenFileDialog();

        //        ofd.Filter = "data files (LiveProcessSnapshot*.data)|*.data";
        //        ofd.FilterIndex = 0;
        //        ofd.ShowDialog();
        //        string targetfile = ofd.FileName;
        //        treeView4.ImageList = imageList1;
        //        treeView5.ImageList = imageList1;

        //        using (Stream file = File.Open(targetfile, FileMode.Open))
        //        {
        //            BinaryFormatter _data = new BinaryFormatter();
        //            object obj = _data.Deserialize(file);

        //            TreeNode[] _Nodes = (obj as IEnumerable<TreeNode>).ToArray();
        //            treeView4.Nodes.AddRange(_Nodes);
        //        }


        //        OpenFileDialog ofd2 = new OpenFileDialog();

        //        ofd2.Filter = "data2 files (ClosedProcessSnapshot*.data2)|*.data2";
        //        ofd2.FilterIndex = 0;
        //        ofd2.ShowDialog();
        //        string targetfile2 = ofd2.FileName;

        //        using (Stream file = File.Open(targetfile2, FileMode.Open))
        //        {
        //            BinaryFormatter _data = new BinaryFormatter();
        //            object obj = _data.Deserialize(file);

        //            TreeNode[] _Nodes = (obj as IEnumerable<TreeNode>).ToArray();
        //            treeView5.Nodes.AddRange(_Nodes);
        //        }

        //        Thread.Sleep(100);
        //        tabControl3.SelectedIndex = 2;
        //        Thread.Sleep(10);
        //        label1.Text = targetfile;
        //        label2.Text = targetfile2;

        //        MessageBox.Show("Data files loaded in Snapshot1 Tab \n" + targetfile + "\n" + targetfile2);

        //    }
        //    catch (Exception ee)
        //    {

        //        MessageBox.Show(ee.Message);
        //    }
        //}
    }
}
