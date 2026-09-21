using System.ComponentModel;

namespace KeePassFIDO2
{
	partial class FIDO2DevicesControl
	{
		private IContainer components = null;

		protected override void Dispose(bool disposing)
		{
			if (disposing && (components != null))
			{
				components.Dispose();
			}

			base.Dispose(disposing);
		}

		#region Component Designer generated code

		private void InitializeComponent()
		{
			this.layout = new System.Windows.Forms.TableLayoutPanel();
			this.labelDevices = new System.Windows.Forms.Label();
			this.listBoxDevices = new System.Windows.Forms.ListBox();
			this.buttonRemoveDevice = new System.Windows.Forms.Button();
			this.labelDeviceName = new System.Windows.Forms.Label();
			this.textBoxDeviceName = new System.Windows.Forms.TextBox();
			this.buttonAddDevice = new System.Windows.Forms.Button();
			this.labelStatus = new System.Windows.Forms.Label();
			this.layout.SuspendLayout();
			this.SuspendLayout();
			//
			// layout
			//
			this.layout.ColumnCount = 2;
			this.layout.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
			this.layout.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
			this.layout.Dock = System.Windows.Forms.DockStyle.Fill;
			this.layout.Name = "layout";
			this.layout.Padding = new System.Windows.Forms.Padding(6);
			this.layout.RowCount = 6;
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.Controls.Add(this.labelDevices, 0, 0);
			this.layout.Controls.Add(this.listBoxDevices, 0, 1);
			this.layout.Controls.Add(this.buttonRemoveDevice, 0, 2);
			this.layout.Controls.Add(this.labelDeviceName, 0, 3);
			this.layout.Controls.Add(this.textBoxDeviceName, 0, 4);
			this.layout.Controls.Add(this.buttonAddDevice, 1, 4);
			this.layout.Controls.Add(this.labelStatus, 0, 5);
			this.layout.SetColumnSpan(this.labelDevices, 2);
			this.layout.SetColumnSpan(this.listBoxDevices, 2);
			this.layout.SetColumnSpan(this.labelDeviceName, 2);
			this.layout.SetColumnSpan(this.labelStatus, 2);
			//
			// labelDevices
			//
			this.labelDevices.AutoSize = true;
			this.labelDevices.Margin = new System.Windows.Forms.Padding(3, 3, 3, 6);
			this.labelDevices.Name = "labelDevices";
			this.labelDevices.Text = "Дополнительные устройства для открытия базы:";
			//
			// listBoxDevices
			//
			this.listBoxDevices.Dock = System.Windows.Forms.DockStyle.Fill;
			this.listBoxDevices.IntegralHeight = false;
			this.listBoxDevices.Name = "listBoxDevices";
			this.listBoxDevices.TabIndex = 0;
			this.listBoxDevices.SelectedIndexChanged += new System.EventHandler(this.DevicesSelectedIndexChanged);
			//
			// buttonRemoveDevice
			//
			this.buttonRemoveDevice.AutoSize = true;
			this.buttonRemoveDevice.Margin = new System.Windows.Forms.Padding(3, 6, 3, 12);
			this.buttonRemoveDevice.Name = "buttonRemoveDevice";
			this.buttonRemoveDevice.Padding = new System.Windows.Forms.Padding(8, 0, 8, 0);
			this.buttonRemoveDevice.TabIndex = 1;
			this.buttonRemoveDevice.Text = "Удалить выбранное устройство";
			this.buttonRemoveDevice.UseVisualStyleBackColor = true;
			this.buttonRemoveDevice.Click += new System.EventHandler(this.RemoveDeviceButtonClick);
			//
			// labelDeviceName
			//
			this.labelDeviceName.AutoSize = true;
			this.labelDeviceName.Margin = new System.Windows.Forms.Padding(3, 3, 3, 6);
			this.labelDeviceName.Name = "labelDeviceName";
			this.labelDeviceName.Text = "Название нового устройства:";
			//
			// textBoxDeviceName
			//
			this.textBoxDeviceName.Anchor = System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
			this.textBoxDeviceName.Name = "textBoxDeviceName";
			this.textBoxDeviceName.TabIndex = 2;
			//
			// buttonAddDevice
			//
			this.buttonAddDevice.AutoSize = true;
			this.buttonAddDevice.Name = "buttonAddDevice";
			this.buttonAddDevice.Padding = new System.Windows.Forms.Padding(8, 0, 8, 0);
			this.buttonAddDevice.TabIndex = 3;
			this.buttonAddDevice.Text = "Добавить устройство";
			this.buttonAddDevice.UseVisualStyleBackColor = true;
			this.buttonAddDevice.Click += new System.EventHandler(this.AddDeviceButtonClick);
			//
			// labelStatus
			//
			this.labelStatus.AutoSize = true;
			this.labelStatus.Dock = System.Windows.Forms.DockStyle.Fill;
			this.labelStatus.Margin = new System.Windows.Forms.Padding(3, 12, 3, 3);
			this.labelStatus.Name = "labelStatus";
			//
			// FIDO2DevicesControl
			//
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.Controls.Add(this.layout);
			this.Name = "FIDO2DevicesControl";
			this.Size = new System.Drawing.Size(500, 300);
			this.layout.ResumeLayout(false);
			this.layout.PerformLayout();
			this.ResumeLayout(false);
		}

		private System.Windows.Forms.TableLayoutPanel layout;
		private System.Windows.Forms.Label labelDevices;
		private System.Windows.Forms.ListBox listBoxDevices;
		private System.Windows.Forms.Button buttonRemoveDevice;
		private System.Windows.Forms.Label labelDeviceName;
		private System.Windows.Forms.TextBox textBoxDeviceName;
		private System.Windows.Forms.Button buttonAddDevice;
		private System.Windows.Forms.Label labelStatus;

		#endregion
	}
}
