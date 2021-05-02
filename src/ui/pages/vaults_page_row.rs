// vaults_page_row.rs
//
// Copyright 2021 Martin Pobaschnig <mpobaschnig@posteo.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later

use adw::{subclass::prelude::*, ActionRowExt, PreferencesRowExt};
use gettextrs::gettext;
use glib::once_cell::sync::Lazy;
use glib::{clone, subclass};
use gtk::glib;
use gtk::glib::subclass::Signal;
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::CompositeTemplate;
use std::cell::RefCell;
use std::process::Command;

use crate::{
    backend::{Backend, BackendError},
    ui::ApplicationWindow,
    vault::*,
    VApplication,
};

mod imp {
    use super::*;

    #[derive(Debug, CompositeTemplate)]
    #[template(resource = "/io/github/mpobaschnig/Vaults/vaults_page_row.ui")]
    pub struct VaultsPageRow {
        #[template_child]
        pub vaults_page_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub open_folder_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub locker_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub settings_button: TemplateChild<gtk::Button>,

        pub spinner: RefCell<gtk::Spinner>,

        pub config: RefCell<Option<VaultConfig>>,

        pub unlock_signal_id: RefCell<Option<glib::SignalHandlerId>>,
        pub save_signal_id: RefCell<Option<glib::SignalHandlerId>>,
        pub remove_signal_id: RefCell<Option<glib::SignalHandlerId>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for VaultsPageRow {
        const NAME: &'static str = "VaultsPageRow";
        type ParentType = gtk::ListBoxRow;
        type Type = super::VaultsPageRow;

        fn new() -> Self {
            Self {
                vaults_page_row: TemplateChild::default(),
                open_folder_button: TemplateChild::default(),
                locker_button: TemplateChild::default(),
                settings_button: TemplateChild::default(),
                config: RefCell::new(None),
                spinner: RefCell::new(gtk::Spinner::new()),
                unlock_signal_id: RefCell::new(None),
                save_signal_id: RefCell::new(None),
                remove_signal_id: RefCell::new(None),
            }
        }

        fn class_init(klass: &mut Self::Class) {
            Self::bind_template(klass);
        }

        fn instance_init(obj: &subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for VaultsPageRow {
        fn constructed(&self, obj: &Self::Type) {
            self.parent_constructed(obj);

            obj.setup_connect_handlers();

            self.open_folder_button.set_visible(false);
        }

        fn signals() -> &'static [Signal] {
            static SIGNALS: Lazy<Vec<Signal>> = Lazy::new(|| {
                vec![
                    Signal::builder("save", &[], glib::Type::UNIT.into()).build(),
                    Signal::builder("remove", &[], glib::Type::UNIT.into()).build(),
                ]
            });
            SIGNALS.as_ref()
        }
    }
    impl WidgetImpl for VaultsPageRow {}
    impl ListBoxRowImpl for VaultsPageRow {}
}

glib::wrapper! {
    pub struct VaultsPageRow(ObjectSubclass<imp::VaultsPageRow>)
        @extends gtk::Widget, gtk::ListBoxRow;
}

impl VaultsPageRow {
    pub fn connect_remove<F: Fn() + 'static>(&self, callback: F) -> glib::SignalHandlerId {
        self.connect_local("remove", false, move |_| {
            callback();
            None
        })
        .unwrap()
    }

    pub fn connect_save<F: Fn() + 'static>(&self, callback: F) -> glib::SignalHandlerId {
        self.connect_local("save", false, move |_| {
            callback();
            None
        })
        .unwrap()
    }

    pub fn new(vault: Vault) -> Self {
        let object: Self = glib::Object::new(&[]).expect("Failed to create VaultsPageRow");

        let self_ = &imp::VaultsPageRow::from_instance(&object);

        match (vault.get_name(), vault.get_config()) {
            (Some(name), Some(config)) => {
                self_.vaults_page_row.set_title(Some(&name));
                self_.config.replace(Some(config));
            }
            (_, _) => {
                log::error!("Vault(s) not initialised!");
            }
        }

        if vault.is_mounted() {
            object.set_vault_row_state_opened();
        }

        if !vault.is_backend_available() {
            object.set_vault_row_state_backend_unavailable();
        }

        object
    }

    pub fn setup_connect_handlers(&self) {
        let self_ = imp::VaultsPageRow::from_instance(&self);

        self_
            .open_folder_button
            .connect_clicked(clone!(@weak self as obj => move |_| {
                obj.open_folder_button_clicked();
            }));

        self_
            .locker_button
            .connect_clicked(clone!(@weak self as obj => move |_| {
                obj.locker_button_clicked();
            }));

        self_
            .settings_button
            .connect_clicked(clone!(@weak self as obj => move |_| {
                obj.settings_button_clicked();
            }));
    }

    fn open_folder_button_clicked(&self) {
        let self_ = imp::VaultsPageRow::from_instance(&self);

        let output_res = Command::new("xdg-open")
            .arg(&self_.config.borrow().as_ref().unwrap().mount_directory)
            .output();

        if let Err(e) = output_res {
            log::error!("Failed to open folder: {}", e);
        }
    }

    fn locker_button_clicked_is_mounted(&self, vault: Vault) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.open_folder_button.set_sensitive(false);

        *self_.spinner.borrow_mut() = gtk::Spinner::new();
        let spinner = self_.spinner.borrow().clone();
        self_.locker_button.set_child(Some(&spinner));

        spinner.start();

        enum Message {
            Finished,
            Error(BackendError),
        }

        let (sender, receiver) = glib::MainContext::channel(glib::PRIORITY_DEFAULT);
        let vault_config = vault.get_config().clone().unwrap();
        std::thread::spawn(move || match Backend::close(&vault_config) {
            Ok(_) => {
                let _ = sender.send(Message::Finished);
            }
            Err(e) => {
                let _ = sender.send(Message::Error(e));
            }
        });

        let locker_button = self_.locker_button.clone();
        let open_folder_button = self_.open_folder_button.clone();
        let settings_button = self_.settings_button.clone();
        let vaults_page_row = self_.vaults_page_row.clone();
        receiver.attach(None, move |message| {
            match message {
                Message::Finished => {
                    locker_button.set_icon_name(&"changes-prevent-symbolic");
                    locker_button.set_tooltip_text(Some(&gettext("Open Vault")));
                    open_folder_button.set_visible(false);
                    open_folder_button.set_sensitive(false);
                    settings_button.set_sensitive(true);
                }
                Message::Error(e) => {
                    log::error!("Error closing vault: {}", &e);

                    locker_button.set_icon_name(&"changes-allow-symbolic");
                    locker_button.set_tooltip_text(Some(&gettext("Close Vault")));
                    open_folder_button.set_visible(true);
                    open_folder_button.set_sensitive(true);
                    settings_button.set_sensitive(false);

                    let vault_name = vaults_page_row.get_title().unwrap().to_string();
                    gtk::glib::MainContext::default().spawn_local(async move {
                        let window = gtk::gio::Application::get_default()
                            .unwrap()
                            .downcast_ref::<VApplication>()
                            .unwrap()
                            .get_active_window()
                            .unwrap()
                            .clone();
                        let info_dialog = gtk::MessageDialogBuilder::new()
                            .message_type(gtk::MessageType::Error)
                            .transient_for(&window)
                            .modal(true)
                            .buttons(gtk::ButtonsType::Close)
                            .text(&vault_name)
                            .secondary_text(&format!("{}", e))
                            .build();

                        info_dialog.run_future().await;

                        info_dialog.close();
                    });
                }
            }

            spinner.stop();

            glib::Continue(true)
        });
    }

    fn locker_button_clicked_is_not_mounted(&self, vault: Vault, password: String) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.settings_button.set_sensitive(false);
        self_.open_folder_button.set_sensitive(false);

        *self_.spinner.borrow_mut() = gtk::Spinner::new();
        let spinner = self_.spinner.borrow().clone();
        self_.locker_button.set_child(Some(&spinner));

        spinner.start();

        enum Message {
            Finished,
            Error(BackendError),
        }

        let (sender, receiver) = glib::MainContext::channel(glib::PRIORITY_DEFAULT);
        let vault_config = vault.get_config().clone().unwrap();
        std::thread::spawn(move || match Backend::open(&vault_config, password) {
            Ok(_) => {
                let _ = sender.send(Message::Finished);
            }
            Err(e) => {
                let _ = sender.send(Message::Error(e));
            }
        });

        let locker_button = self_.locker_button.clone();
        let open_folder_button = self_.open_folder_button.clone();
        let settings_button = self_.settings_button.clone();
        let vaults_page_row = self_.vaults_page_row.clone();
        receiver.attach(None, move |message| {
            match message {
                Message::Finished => {
                    locker_button.set_icon_name(&"changes-allow-symbolic");
                    locker_button.set_tooltip_text(Some(&gettext("Close Vault")));
                    open_folder_button.set_visible(true);
                    open_folder_button.set_sensitive(true);
                    settings_button.set_sensitive(false);
                }
                Message::Error(e) => {
                    log::error!("Error opening vault: {}", &e);

                    locker_button.set_icon_name(&"changes-prevent-symbolic");
                    locker_button.set_tooltip_text(Some(&gettext("Open Vault")));
                    open_folder_button.set_visible(false);
                    open_folder_button.set_sensitive(false);
                    settings_button.set_sensitive(true);

                    let vault_name = vaults_page_row.get_title().unwrap().to_string();
                    gtk::glib::MainContext::default().spawn_local(async move {
                        let window = gtk::gio::Application::get_default()
                            .unwrap()
                            .downcast_ref::<VApplication>()
                            .unwrap()
                            .get_active_window()
                            .unwrap()
                            .clone();
                        let info_dialog = gtk::MessageDialogBuilder::new()
                            .message_type(gtk::MessageType::Error)
                            .transient_for(&window)
                            .modal(true)
                            .buttons(gtk::ButtonsType::Close)
                            .text(&vault_name)
                            .secondary_text(&format!("{}", e))
                            .build();

                        info_dialog.run_future().await;

                        info_dialog.close();
                    });
                }
            }

            spinner.stop();

            glib::Continue(true)
        });
    }

    pub fn locker_button_clicked(&self) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        if self_.spinner.borrow().get_spinning() {
            return;
        }

        let vault = self.get_vault();

        if !vault.is_backend_available() {
            self.set_vault_row_state_backend_unavailable();
            return;
        } else {
            self.set_vault_row_state_backend_available();
        }

        if !self.is_mounted() {
            if self_.open_folder_button.is_visible() {
                self.set_vault_row_state_closed();
                return;
            }

            let ancestor = self.get_ancestor(ApplicationWindow::static_type()).unwrap();
            let window = ancestor.downcast_ref::<ApplicationWindow>().unwrap();

            window.call_unlock(self);
        } else {
            if !self_.open_folder_button.is_visible() {
                self.set_vault_row_state_opened();
                return;
            }

            self.locker_button_clicked_is_mounted(self.get_vault());
        }
    }

    fn settings_button_clicked(&self) {
        let ancestor = self.get_ancestor(ApplicationWindow::static_type()).unwrap();
        let window = ancestor.downcast_ref::<ApplicationWindow>().unwrap();

        window.call_settings(self);
    }

    pub fn get_vault(&self) -> Vault {
        let self_ = imp::VaultsPageRow::from_instance(&self);
        let name = self_.vaults_page_row.get_title();
        let config = self_.config.borrow().clone();
        match (name, config) {
            (Some(name), Some(config)) => Vault::new(
                name.to_string(),
                config.backend,
                config.encrypted_data_directory,
                config.mount_directory,
            ),
            (_, _) => {
                log::error!("Vault not initialised!");
                Vault::new_none()
            }
        }
    }

    pub fn set_vault(&self, vault: Vault) {
        let self_ = imp::VaultsPageRow::from_instance(&self);
        let name = vault.get_name();
        let config = vault.get_config();
        match (name, config) {
            (Some(name), Some(config)) => {
                self_.vaults_page_row.set_title(Some(&name));
                self_.config.replace(Some(config));
            }
            (_, _) => {
                log::error!("Vault not initialised!");
            }
        }
    }

    pub fn get_name(&self) -> String {
        let self_ = imp::VaultsPageRow::from_instance(&self);
        self_.vaults_page_row.get_title().unwrap().to_string()
    }

    fn is_mounted(&self) -> bool {
        if self.get_vault().is_mounted() {
            true
        } else {
            false
        }
    }

    fn set_vault_row_state_opened(&self) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.locker_button.set_icon_name(&"changes-allow-symbolic");
        self_
            .locker_button
            .set_tooltip_text(Some(&gettext("Close Vault")));
        self_.open_folder_button.set_visible(true);
        self_.open_folder_button.set_sensitive(true);
        self_.settings_button.set_sensitive(false);
    }

    fn set_vault_row_state_closed(&self) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_
            .locker_button
            .set_icon_name(&"changes-prevent-symbolic");
        self_
            .locker_button
            .set_tooltip_text(Some(&gettext("Open Vault")));
        self_.open_folder_button.set_visible(false);
        self_.open_folder_button.set_sensitive(true);
        self_.settings_button.set_sensitive(true);
    }

    pub fn set_vault_row_state_backend_unavailable(&self) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_
            .vaults_page_row
            .set_subtitle(Some(&gettext("Backend is not installed.")));
        self_.locker_button.set_sensitive(false);
    }

    pub fn set_vault_row_state_backend_available(&self) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.vaults_page_row.set_subtitle(Some(""));
        self_.locker_button.set_sensitive(true);
    }

    pub fn unlock(&self, password: String) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        let vault = self.get_vault();

        if !vault.is_backend_available() {
            self.set_vault_row_state_backend_unavailable();
            return;
        } else {
            self.set_vault_row_state_backend_available();
        }

        if !self.is_mounted() {
            if self_.open_folder_button.is_visible() {
                self.set_vault_row_state_closed();
                return;
            }

            self.locker_button_clicked_is_not_mounted(vault, password);
        } else {
            if !self_.open_folder_button.is_visible() {
                self.set_vault_row_state_opened();
                return;
            }

            self.locker_button_clicked_is_mounted(self.get_vault());
        }
    }

    pub fn set_unlock_handler_id(&self, id: glib::SignalHandlerId) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.unlock_signal_id.replace(Some(id));
    }

    pub fn get_unlock_handler_id(&self) -> glib::SignalHandlerId {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.unlock_signal_id.borrow_mut().take().unwrap()
    }

    pub fn set_save_handler_id(&self, id: glib::SignalHandlerId) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.save_signal_id.replace(Some(id));
    }

    pub fn get_save_handler_id(&self) -> glib::SignalHandlerId {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.save_signal_id.borrow_mut().take().unwrap()
    }

    pub fn set_remove_handler_id(&self, id: glib::SignalHandlerId) {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.remove_signal_id.replace(Some(id));
    }

    pub fn get_remove_handler_id(&self) -> glib::SignalHandlerId {
        let self_ = imp::VaultsPageRow::from_instance(self);

        self_.remove_signal_id.borrow_mut().take().unwrap()
    }
}
