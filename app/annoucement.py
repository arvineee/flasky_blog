from flask import render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from .forms import AnnouncementForm
from .models import Announcement
from . import db

@bp.route('/announcement', methods=['GET', 'POST'])
@login_required
def announcement():
    if not current_user.is_admin:
        flash('You are not authorized to view this page.', 'danger')
        return redirect(url_for('index'))

    form = AnnouncementForm()
    if form.validate_on_submit():
        new_announcement = Announcement(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(new_announcement)
        db.session.commit()
        flash('Announcement created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('announcement.html', form=form)
