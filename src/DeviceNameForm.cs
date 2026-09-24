using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Диалог перед созданием credential для мастер‑ключа: пояснение, название устройства и — при смене
	/// мастер‑ключа базы с устройствами — выбор, сохранить ли их
	/// </summary>
	public partial class DeviceNameForm : Form
	{
		private readonly string deviceList;
		private readonly bool changingKey;

		/// <param name="existingDevices">Подписи устройств базы, мастер‑ключ которой меняется; пусто для новой базы</param>
		public DeviceNameForm(IList<string> existingDevices)
		{
			InitializeComponent();
			labelDescription.Text =
				"Сейчас будет создан новый FIDO2 credential для этой базы данных.\n" +
				"Введите ниже название устройства, которым создаётся ключ — оно отличает его от других " +
				"в списке устройств базы. Если оставить пустым, подпись будет составлена из типа устройства и даты.\n\n" +
				"Вам потребуется:\n" +
				"1. FIDO2‑ключ с поддержкой hmac-secret/PRF (YubiKey 5 и др.), Windows Hello или телефон\n" +
				"2. Ввести PIN‑код ключа\n" +
				"3. Подтвердить создание credential (обычно нажатием кнопки на ключе)\n\n" +
				"Credential сохраняется на самом устройстве — файлы рядом с базой не нужны.\n" +
				"Другие устройства: Файл → Параметры базы → вкладка «FIDO2».";

			changingKey = existingDevices != null && existingDevices.Count > 0;
			checkBoxKeepDevices.Visible = changingKey;
			labelKeepDevices.Visible = changingKey;
			if (changingKey)
			{
				deviceList = "«" + string.Join("», «", existingDevices) + "»";
				checkBoxKeepDevices.CheckedChanged += (s, e) => UpdateKeepDevicesText();
				UpdateKeepDevicesText();
			}
		}

		/// <summary>Введённое название без пробелов по краям; пусто, если не указано. Доступно и после закрытия формы</summary>
		public string DeviceName { get; private set; } = string.Empty;

		/// <summary>Сохранить остальные устройства базы (перешифровать их обёртки на новый ключ)</summary>
		public bool KeepDevices { get; private set; }

		private void UpdateKeepDevicesText()
		{
			if (checkBoxKeepDevices.Checked)
			{
				labelKeepDevices.ForeColor = SystemColors.GrayText;
				labelKeepDevices.Text = $"Устройства {deviceList} продолжат открывать базу без повторной регистрации.";
			}
			else
			{
				labelKeepDevices.ForeColor = Color.Firebrick;
				labelKeepDevices.Text = $"Устройства {deviceList} будут удалены из базы. " +
				                        "Открыть базу можно будет только новым устройством.";
			}
		}

		protected override void OnFormClosing(FormClosingEventArgs e)
		{
			DeviceName = textBoxDeviceName.Text.Trim();
			KeepDevices = changingKey && checkBoxKeepDevices.Checked;
			base.OnFormClosing(e);
		}
	}
}
