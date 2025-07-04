/* eslint-disable no-unused-vars */
import React, { useContext, useState } from 'react'
import './Navbar.css'
import { assets } from '../../assets/assets'
import { Link } from 'react-router-dom';
import { StoreContext } from '../../context/StoreContext';

// eslint-disable-next-line react/prop-types
const Navbar = ({setShowLogin}) => {

    const [menu,setMenu] = useState("menu");
    const {getTotalCartAmount} = useContext(StoreContext);
    const user = JSON.parse(localStorage.getItem('user'));

  return (
    <div className='navbar'>
        <Link to ='/'><img src={assets.logo} alt="" className="logo"/></Link>
        <ul className="navbar-menu">
          <Link to='/' onClick={()=>setMenu("home")} className={menu==="home"?"active":""}>home</Link>
          <a href='#explore-menu' onClick={()=>setMenu("menu")} className={menu==="menu"?"active":""}>menu</a>
          <a href='#app-download' onClick={()=>setMenu("mobile-app")} className={menu==="mobile-app"?"active":""}>mobile-app</a>
          <a href='#footer' onClick={()=>setMenu("contact-us")} className={menu==="contact-us"?"active":""}>contact us</a>
        </ul>
        <div className="navbar-right">
          <div className="navbar-search-icon">
            <Link to='/cart'><img src={assets.basket_icon} alt="" /></Link>
            <div className={getTotalCartAmount()===0?"":"dot"}></div>
            <div>
              {user ? (
                <button>{user.name || user.role}</button>
              ) : (
                <button onClick={()=>setShowLogin(true)}>sign in</button>
              )}
            </div>
          </div>
        </div>
    </div>
  )
}

export default Navbar
