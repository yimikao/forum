package models

import (
	"errors"
	"html"
	"log"
	"os"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

// A user can:
// i. Signup
// ii. Login
// iii. Update his details
// iv. Shutdown his account

type User struct {
	ID        uint32    `gorm:"primary_key;auto_increment" json:"id"`
	Username  string    `gorm:"size:255;not null;unique" json:"username"`
	Email     string    `gorm:"size:100;not null;unique" json:"email"`
	Password  string    `gorm:"size:100;not null;" json:"password"`
	Avatar    string    `gorm:"size:255;null;" json:"avatar"`
	CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
}

//a few things before saving new user record
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err

}
func (u *User) BeforeSave() error {
	hashedPassword, err := hashPassword(u.Password)

	if err != nil {
		return err
	}
	u.Password = hashedPassword
	return nil
}

//Prepare the User struct for saving
func (u *User) Prepare() {
	u.Username = html.EscapeString(strings.TrimSpace(u.Username))
	u.Email = html.EscapeString(strings.TrimSpace(u.Email))
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
}

func (u *User) AfterFind() (err error) {
	if err != nil {
		return err
	}
	if u.Avatar != "" {
		u.Avatar = os.Getenv("DO_SPACES_URL") + u.Avatar
	}
	return nil
}

//validate user actions
func (u *User) Validate(action string) map[string]string {
	errorMessages := make(map[string]string)
	var err error

	switch strings.ToLower(action) {
	case "update":
		if u.Email == "" {
			err = errors.New("required Email")
			errorMessages["required_email"] = err.Error()
		}
		if u.Email != "" {
			if err = checkmail.ValidateFormat(u.Email); err != nil {
				err = errors.New("invalid Email")
				errorMessages["invalid_email"] = err.Error()
			}
		}
	case "login":
		if u.Password == "" {
			err = errors.New("required password")
			errorMessages["required_password"] = err.Error()
		}
		if u.Email == "" {
			err = errors.New("required email")
			errorMessages["required_email"] = err.Error()
		}
		if u.Email != "" {
			if err = checkmail.ValidateFormat(u.Email); err != nil {
				err = errors.New("invalid email")
				errorMessages["invalid_email"] = err.Error()
			}
		}
	case "forgotpassword":
		if u.Email == "" {
			err = errors.New("required password")
			errorMessages["required_password"] = err.Error()
		}
		if u.Email != "" {
			if err = checkmail.ValidateFormat(u.Email); err != nil {
				err = errors.New("invalid email")
				errorMessages["invalid_email"] = err.Error()
			}
		}
	default:
		if u.Username == "" {
			err = errors.New("required username")
			errorMessages["required_username"] = err.Error()
		}

		if u.Password == "" {
			err = errors.New("required password")
			errorMessages["required_password"] = err.Error()
		}

		if u.Password != "" && len(u.Password) < 6 {
			err = errors.New("password should be atleast 6 characters")
			errorMessages["invalid_password"] = err.Error()
		}

		if u.Email == "" {
			err = errors.New("required email")
			errorMessages["required_email"] = err.Error()
		}
		if u.Email != "" {
			if err = checkmail.ValidateFormat(u.Email); err != nil {
				err = errors.New("invalid email")
				errorMessages["invalid_email"] = err.Error()
			}
		}
	}
	return errorMessages
}

func (u *User) SaveUser(db *gorm.DB) (*User, error) {
	err := db.Debug().Create(&u).Error
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (u *User) FindAllUsers(db *gorm.DB) (*[]User, error) {
	users := []User{}
	err := db.Debug().Model(&User{}).Limit(100).Find(&users).Error
	if err != nil {
		return nil, err
	}
	return &users, nil
}

func (u *User) FindUserById(db *gorm.DB, id uint32) (*User, error) {
	//u := User{}
	err := db.Debug().Model(&User{}).Where("id = ?", id).Take(&u).Error
	if err != nil {
		return nil, err
	}
	if gorm.IsRecordNotFoundError(err) {
		return nil, errors.New("User not found")
	}
	return u, err
}

func (u *User) UpdateUser(db *gorm.DB, id int32) (*User, error) {

	if u.Password != "" {
		err := u.BeforeSave()
		if err != nil {
			log.Fatal(err)
		}

		db = db.Debug().Model(&User{}).Where("id = ?", id).Take(&User{}).UpdateColumns(
			map[string]interface{}{
				"password":   u.Password,
				"email":      u.Email,
				"updated_at": time.Now(),
			},
		)
	}

	db = db.Debug().Model(&User{}).Where("id = ?", id).Take(&User{}).UpdateColumns(
		map[string]interface{}{
			"email":     u.Email,
			"update_at": time.Now(),
		},
	)
	if db.Error != nil {
		return nil, db.Error
	}
	// This is to display the updated user

	if err := db.Debug().Model(&User{}).Where("id = ? ", id).Take(&u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

func (u *User) UpdateUserAvatar(db *gorm.DB, id int32) (*User, error) {
	db = db.Debug().Model(&User{}).Where("id = ?", id).Take(&User{}).UpdateColumns(
		map[string]interface{}{
			"avatar":    u.Avatar,
			"update_at": time.Now(),
		},
	)
	if db.Error != nil {
		return nil, db.Error
	}
	// This is to display the updated user
	err := db.Debug().Model(&User{}).Where("id = ?", id).Take(&u).Error
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (u *User) DeleteUser(db *gorm.DB, id int32) (int64, error) {
	db = db.Debug().Model(&User{}).Where("id = ?", id).Take(&User{}).Delete(&u)
	if db.Error != nil {
		return 0, db.Error
	}
	return db.RowsAffected, nil
}

func (u *User) UpdatePassword(db *gorm.DB) error {
	err := u.BeforeSave()
	if err != nil {
		log.Fatal(err)
	}
	db = db.Debug().Model(&User{}).Where("email = ?", u.Email).Take(&User{}).UpdateColumns(
		map[string]interface{}{
			"password":  u.Password,
			"update_at": time.Now(),
		},
	)
	if db.Error != nil {
		return db.Error
	}
	return nil
}
