using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Drawing.Imaging;
using System.Windows.Forms;

namespace ETWPM2Monitor2
{
    class ImageBitmap_Info
    {
      
        public static void MakeImageBMP(string _Str_Bytes)
        {
            try
            {
                string[] ss = _Str_Bytes.Split('-');
                byte[] _bytes = new byte[ss.Length];

                for (int i = 0; i < ss.Length; i++)
                {
                    _bytes[i] = Convert.ToByte(ss[i], 16);

                }

                Bitmap _image = InjectecBytestoBitmap(10, _bytes.Length / 10, _bytes);
                _image.Save("LastInjectedPayloadDetected.bmp");

            }
            catch (Exception)
            {


            }

        }


        public static Bitmap InjectecBytestoBitmap(int x, int y, byte[] data)
        {
            Bitmap Img = null;
            try
            {
                Img = new Bitmap(x, y, PixelFormat.Format8bppIndexed);   

                BitmapData Pixels = Img.LockBits(
                    new Rectangle(0, 0, Img.Width, Img.Height),
                    ImageLockMode.WriteOnly, Img.PixelFormat);

                Marshal.Copy(data, 0, Pixels.Scan0, data.Length);

                Img.UnlockBits(Pixels);

                return Img;
            }
            catch (Exception)
            {

               
            }

            return Img;
        }

        public static void Lines(string _Str_Bytes)
        {

            try
            {
                string[] ss = _Str_Bytes.Split('-');
                byte[] _bytes = new byte[ss.Length];
                Bitmap _image2 = null;

                _image2 = new Bitmap(400, 250, System.Drawing.Imaging.PixelFormat.Format32bppPArgb);

                Graphics _graphics = Graphics.FromImage(_image2);

                for (int i = 0; i < ss.Length; i++)
                {
                    _bytes[i] = Convert.ToByte(ss[i], 16);
                    
                    Pen pen = new Pen(Color.FromArgb((int)Convert.ToDouble(_bytes[i]),
                        (int)Convert.ToDouble(_bytes[i] ), 
                        (int)Convert.ToDouble(_bytes[i] ),
                        (int)Convert.ToDouble(_bytes[i] )), 2);

                    _graphics.DrawLine(pen, 120, i, (int) Convert.ToDecimal( _bytes[i]), (int)Convert.ToDecimal(_bytes[i]));
 
                }

                _image2.Save("LastInjectedPayloadDetected2.png");

            }
            catch (Exception e)
            {
                //MessageBox.Show(e.Message);

            }

           
        }

    }
}
